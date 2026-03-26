"""
Analytics endpoints — complex PostgreSQL queries.

THIS IS WHERE YOU PROVE POSTGRESQL DEPTH.

Every query uses features MongoDB can't do (or does poorly):
- FILTER: conditional aggregation in one pass
- date_trunc: time-bucketed grouping
- Window functions: running calculations across rows
- CASE: categorize values into buckets
- make_interval: safe parameterized time ranges
- COALESCE + NULLIF: handle division by zero
- Composite indexes: queries hit indexes, not full scans

Each endpoint is designed to power one dashboard chart.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from Vigil.db.engine import get_db

router = APIRouter(
    prefix="/v1/analytics",
    tags=["Analytics"],
)


@router.get("/overview")
async def analytics_overview(
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
):
    """
    Dashboard overview — key metrics for the last N hours.

    POSTGRESQL FEATURES USED:
    - FILTER: count blocked/allowed/challenged in one query
      instead of 4 separate queries
    - COUNT(DISTINCT ...): unique fingerprints and IPs
    - COALESCE: return 0 instead of NULL for empty tables
    - NULLIF: prevent division by zero in block rate calc
    - make_interval: safe parameterized time range

    This single query replaces what would need 6+ MongoDB
    aggregation pipeline stages.
    """
    query = text("""
        SELECT
            COUNT(*) AS total_requests,

            COUNT(*) FILTER (
                WHERE action_taken = 'allow'
            ) AS allowed,

            COUNT(*) FILTER (
                WHERE action_taken = 'block'
            ) AS blocked,

            COUNT(*) FILTER (
                WHERE action_taken = 'challenge'
            ) AS challenged,

            COUNT(*) FILTER (
                WHERE action_taken = 'shadowban'
            ) AS shadowbanned,

            COUNT(*) FILTER (
                WHERE is_suspicious = true
            ) AS suspicious,

            COUNT(DISTINCT fingerprint_hash)
                AS unique_fingerprints,

            COUNT(DISTINCT ip_address)
                AS unique_ips,

            COALESCE(
                ROUND(AVG(threat_score)::numeric, 4),
                0
            ) AS avg_threat_score,

            COALESCE(
                ROUND(
                    COUNT(*) FILTER (
                        WHERE action_taken = 'block'
                    )::numeric
                    / NULLIF(COUNT(*), 0) * 100,
                    2
                ),
                0
            ) AS block_rate_pct

        FROM requests
        WHERE created_at > NOW() - make_interval(
            hours => :hours
        )
    """)

    result = await db.execute(query, {"hours": hours})
    row = result.mappings().first()
    return dict(row) if row else {}


@router.get("/timeline")
async def analytics_timeline(
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
):
    """
    Hourly traffic breakdown for timeline chart.

    POSTGRESQL FEATURES USED:
    - date_trunc('hour', ...): rounds timestamps to hour
      boundaries, creating time buckets
    - FILTER: count blocked/allowed per hour in one pass
    - GROUP BY + ORDER BY: aggregate and sort

    Dashboard uses this for the stacked area chart
    showing allowed (green) vs blocked (red) over time.
    """
    query = text("""
        SELECT
            date_trunc('hour', created_at)
                AS time_bucket,
            COUNT(*) AS total,
            COUNT(*) FILTER (
                WHERE action_taken = 'block'
            ) AS blocked,
            COUNT(*) FILTER (
                WHERE action_taken = 'allow'
            ) AS allowed,
            COUNT(DISTINCT fingerprint_hash)
                AS unique_fingerprints,
            ROUND(
                AVG(threat_score)::numeric, 4
            ) AS avg_score
        FROM requests
        WHERE created_at > NOW() - make_interval(
            hours => :hours
        )
        GROUP BY date_trunc('hour', created_at)
        ORDER BY time_bucket DESC
    """)

    result = await db.execute(query, {"hours": hours})
    rows = result.mappings().all()

    return [
        {
            **dict(row),
            "time_bucket": (
                row["time_bucket"].isoformat()
                if row["time_bucket"]
                else None
            ),
        }
        for row in rows
    ]


@router.get("/top-threats")
async def top_threats(
    hours: int = 24,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
):
    """
    Top threatening fingerprints by average score.

    POSTGRESQL FEATURES USED:
    - GROUP BY + aggregate functions: per-fingerprint stats
    - HAVING: filter groups AFTER aggregation
      (only show fingerprints with avg score > 0.3)
    - COUNT(*) FILTER: conditional count per group
    - MIN/MAX: first and last seen times
    - COUNT(DISTINCT path): how many unique paths accessed

    HAVING vs WHERE:
    WHERE filters individual rows BEFORE grouping
    HAVING filters groups AFTER aggregation
    "Show me fingerprints whose AVERAGE score > 0.3"
    needs HAVING because the average doesn't exist
    until after GROUP BY runs.
    """
    query = text("""
        SELECT
            fingerprint_hash,
            COUNT(*) AS total_requests,

            COUNT(*) FILTER (
                WHERE action_taken = 'block'
            ) AS times_blocked,

            COUNT(DISTINCT ip_address)
                AS distinct_ips,

            ROUND(
                AVG(threat_score)::numeric, 4
            ) AS avg_threat_score,

            ROUND(
                MAX(threat_score)::numeric, 4
            ) AS max_threat_score,

            MIN(created_at) AS first_seen,
            MAX(created_at) AS last_seen,

            COUNT(DISTINCT path)
                AS unique_paths,

            ROUND(
                COUNT(*) FILTER (
                    WHERE status_code IN (401, 403)
                )::numeric
                / NULLIF(COUNT(*), 0) * 100,
                2
            ) AS failure_rate_pct

        FROM requests
        WHERE created_at > NOW() - make_interval(
            hours => :hours
        )
        GROUP BY fingerprint_hash
        HAVING AVG(threat_score) > 0.3
        ORDER BY AVG(threat_score) DESC
        LIMIT :limit_val
    """)

    result = await db.execute(
        query,
        {"hours": hours, "limit_val": limit},
    )
    rows = result.mappings().all()

    return [
        {
            **dict(row),
            "first_seen": (
                row["first_seen"].isoformat()
                if row["first_seen"]
                else None
            ),
            "last_seen": (
                row["last_seen"].isoformat()
                if row["last_seen"]
                else None
            ),
        }
        for row in rows
    ]


@router.get("/attack-type-distribution")
async def attack_type_distribution(
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
):
    """
    Breakdown of attack types for pie chart.

    POSTGRESQL FEATURES USED:
    - Window function SUM() OVER (): calculates the total
      count across ALL rows, available in each row.
      This lets us compute percentage without a subquery.

    Window functions are one of PostgreSQL's most powerful
    features. They compute values across a "window" of
    related rows without collapsing them into one row
    (unlike GROUP BY).
    """
    query = text("""
        SELECT
            attack_type,
            COUNT(*) AS count,
            ROUND(
                COUNT(*)::numeric
                / NULLIF(
                    SUM(COUNT(*)) OVER (), 0
                ) * 100,
                1
            ) AS percentage
        FROM attack_sessions
        WHERE created_at > NOW() - make_interval(
            hours => :hours
        )
        GROUP BY attack_type
        ORDER BY count DESC
    """)

    result = await db.execute(query, {"hours": hours})
    return [dict(row) for row in result.mappings().all()]


@router.get("/top-targeted-endpoints")
async def top_targeted_endpoints(
    hours: int = 24,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
):
    """
    Most attacked API endpoints.

    Shows which paths receive the most suspicious traffic.
    Useful for identifying which resources attackers target.
    """
    query = text("""
        SELECT
            path,
            COUNT(*) AS total_requests,
            COUNT(*) FILTER (
                WHERE action_taken = 'block'
            ) AS blocked_count,
            ROUND(
                AVG(threat_score)::numeric, 4
            ) AS avg_threat_score
        FROM requests
        WHERE created_at > NOW() - make_interval(
            hours => :hours
        )
        AND threat_score > 0.3
        GROUP BY path
        ORDER BY COUNT(*) DESC
        LIMIT :limit_val
    """)

    result = await db.execute(
        query,
        {"hours": hours, "limit_val": limit},
    )
    return [dict(row) for row in result.mappings().all()]


@router.get("/score-distribution")
async def score_distribution(
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
):
    """
    Threat score histogram — how many requests at each
    score level.

    POSTGRESQL FEATURES USED:
    - CASE expression: categorizes continuous values
      into discrete buckets. Like a switch statement
      in SQL. Each request's score is placed into one
      of 10 buckets: 0.0-0.1, 0.1-0.2, etc.

    Dashboard uses this for a bar chart showing the
    distribution of threat scores. Most requests
    should be in the 0.0-0.1 bucket (normal traffic).
    """
    query = text("""
        SELECT
            CASE
                WHEN threat_score < 0.1 THEN '0.0-0.1'
                WHEN threat_score < 0.2 THEN '0.1-0.2'
                WHEN threat_score < 0.3 THEN '0.2-0.3'
                WHEN threat_score < 0.4 THEN '0.3-0.4'
                WHEN threat_score < 0.5 THEN '0.4-0.5'
                WHEN threat_score < 0.6 THEN '0.5-0.6'
                WHEN threat_score < 0.7 THEN '0.6-0.7'
                WHEN threat_score < 0.8 THEN '0.7-0.8'
                WHEN threat_score < 0.9 THEN '0.8-0.9'
                ELSE '0.9-1.0'
            END AS bucket,
            COUNT(*) AS count
        FROM requests
        WHERE created_at > NOW() - make_interval(
            hours => :hours
        )
        GROUP BY bucket
        ORDER BY bucket
    """)

    result = await db.execute(query, {"hours": hours})
    return [dict(row) for row in result.mappings().all()]


@router.get(
    "/fingerprint/{fingerprint_hash}/history"
)
async def fingerprint_history(
    fingerprint_hash: str,
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
):
    """
    Per-fingerprint request history grouped by minute.

    POSTGRESQL FEATURES USED:
    - date_trunc('minute', ...): group by minute for
      fine-grained timeline
    - FILTER: separate blocked count from total

    Dashboard uses this for the fingerprint detail page
    showing request volume over time with blocked
    requests highlighted.
    """
    query = text("""
        SELECT
            date_trunc('minute', created_at)
                AS minute,
            COUNT(*) AS requests,
            ROUND(
                AVG(threat_score)::numeric, 4
            ) AS avg_score,
            COUNT(*) FILTER (
                WHERE action_taken = 'block'
            ) AS blocked
        FROM requests
        WHERE fingerprint_hash = :fp_hash
          AND created_at > NOW() - make_interval(
              hours => :hours
          )
        GROUP BY date_trunc('minute', created_at)
        ORDER BY minute DESC
    """)

    result = await db.execute(
        query,
        {"fp_hash": fingerprint_hash, "hours": hours},
    )
    rows = result.mappings().all()

    return [
        {
            **dict(row),
            "minute": (
                row["minute"].isoformat()
                if row["minute"]
                else None
            ),
        }
        for row in rows
    ]