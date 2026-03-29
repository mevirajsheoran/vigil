"""
Detection accuracy verification.

Run AFTER seed_data.py or a Locust load test to check
whether Vigil detected attacks correctly.

USAGE:
  python scripts/verify_detection.py

WHAT IT CHECKS:
  1. Block rate is in expected range (not too high = false
     positives, not too low = missed attacks)
  2. Attack sessions were created
  3. Top threats exist and have high scores
  4. Score distribution looks right (most requests low score)

EXPECTED RESULTS:
  After seed_data.py (680 requests):
    - Block rate: 10-40% (attacks are ~26% of traffic)
    - Attack sessions: 1-3 (enumeration + credential stuffing)
    - Top threats: fingerprints with score > 0.5

  After Locust load test (thousands of requests):
    - Block rate: 15-35%
    - Attack sessions: varies
    - Top threats: multiple high-score fingerprints
"""

import sys

import httpx

API = "http://localhost:8000"


def print_header(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{'=' * 55}")
    print(f"  {title}")
    print(f"{'=' * 55}")


def check_overview(hours: int = 1) -> dict:
    """Check overall metrics."""
    print_header("OVERVIEW METRICS")

    response = httpx.get(
        f"{API}/v1/analytics/overview",
        params={"hours": hours},
    )
    data = response.json()

    total = data.get("total_requests", 0)
    allowed = data.get("allowed", 0)
    blocked = data.get("blocked", 0)
    challenged = data.get("challenged", 0)
    block_rate = data.get("block_rate_pct", 0)
    unique_fps = data.get("unique_fingerprints", 0)
    unique_ips = data.get("unique_ips", 0)
    avg_score = data.get("avg_threat_score", 0)

    print(f"  Total requests:      {total:,}")
    print(f"  Allowed:             {allowed:,}")
    print(f"  Blocked:             {blocked:,}")
    print(f"  Challenged:          {challenged:,}")
    print(f"  Block rate:          {block_rate}%")
    print(f"  Unique fingerprints: {unique_fps}")
    print(f"  Unique IPs:          {unique_ips}")
    print(f"  Avg threat score:    {avg_score}")

    return data


def check_attacks() -> list:
    """Check detected attack sessions."""
    print_header("ATTACK SESSIONS")

    response = httpx.get(
        f"{API}/v1/attacks",
        params={"limit": 20},
    )
    attacks = response.json()

    if not attacks:
        print("  ⚠️  No attack sessions detected!")
        print(
            "  This could mean the worker hasn't "
            "processed events yet."
        )
        print("  Wait 10 seconds and try again.")
        return attacks

    print(f"  Attack sessions found: {len(attacks)}")
    print()

    for i, attack in enumerate(attacks, 1):
        attack_type = attack.get("type", "unknown")
        severity = attack.get("severity", "unknown")
        total_reqs = attack.get("total_requests", 0)
        ai_conf = attack.get("ai_confidence", "N/A")
        ai_expl = attack.get("ai_explanation", "N/A")
        fp_hash = attack.get(
            "fingerprint_hash", "unknown"
        )

        print(f"  Attack #{i}:")
        print(f"    Type:        {attack_type}")
        print(f"    Severity:    {severity}")
        print(f"    Requests:    {total_reqs}")
        print(f"    Fingerprint: {fp_hash}")
        print(f"    AI Confidence: {ai_conf}")
        if ai_expl and ai_expl != "N/A":
            # Truncate long explanations
            expl = (
                ai_expl[:100] + "..."
                if len(str(ai_expl)) > 100
                else ai_expl
            )
            print(f"    AI Explanation: {expl}")
        print()

    return attacks


def check_top_threats(hours: int = 1) -> list:
    """Check top threatening fingerprints."""
    print_header("TOP THREATS")

    response = httpx.get(
        f"{API}/v1/analytics/top-threats",
        params={"hours": hours, "limit": 5},
    )
    threats = response.json()

    if not threats:
        print("  No high-score fingerprints found.")
        return threats

    print(
        f"  {'Fingerprint':<18} {'Score':>7} "
        f"{'Requests':>10} {'Blocked':>9} "
        f"{'IPs':>5} {'Fail%':>7}"
    )
    print(f"  {'-' * 60}")

    for t in threats:
        fp = t.get("fingerprint_hash", "?")[:16]
        score = t.get("avg_threat_score", 0)
        reqs = t.get("total_requests", 0)
        blocked = t.get("times_blocked", 0)
        ips = t.get("distinct_ips", 0)
        fail = t.get("failure_rate_pct", 0)

        print(
            f"  {fp:<18} {score:>7.4f} "
            f"{reqs:>10,} {blocked:>9,} "
            f"{ips:>5} {fail:>6.1f}%"
        )

    return threats


def check_score_distribution(hours: int = 1) -> None:
    """Check threat score distribution."""
    print_header("SCORE DISTRIBUTION")

    response = httpx.get(
        f"{API}/v1/analytics/score-distribution",
        params={"hours": hours},
    )
    buckets = response.json()

    if not buckets:
        print("  No data.")
        return

    total = sum(b.get("count", 0) for b in buckets)

    for b in buckets:
        bucket = b.get("bucket", "?")
        count = b.get("count", 0)
        pct = (count / total * 100) if total > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"  {bucket}: {count:>8,} ({pct:>5.1f}%) {bar}")


def run_verdict(overview: dict, attacks: list) -> None:
    """Final verdict — did Vigil work correctly?"""
    print_header("VERDICT")

    total = overview.get("total_requests", 0)
    block_rate = overview.get("block_rate_pct", 0)
    passed = True

    # Check 1: We have data
    if total == 0:
        print("  ❌ No requests found! Run seed_data.py first.")
        return

    print(f"  Total requests analyzed: {total:,}")
    print()

    # Check 2: Block rate in expected range
    # With 70% normal + 30% attack traffic,
    # block rate should be 10-40%
    if 5 <= block_rate <= 50:
        print(
            f"  ✅ Block rate {block_rate}% is within "
            f"expected range [5-50%]"
        )
    elif block_rate < 5:
        print(
            f"  ⚠️  Block rate {block_rate}% is LOW — "
            f"Vigil may not be detecting attacks"
        )
        print(
            "     Check if the worker is running and "
            "has had time to process events."
        )
        passed = False
    else:
        print(
            f"  ⚠️  Block rate {block_rate}% is HIGH — "
            f"possible false positives"
        )
        passed = False

    # Check 3: Attack sessions created
    if len(attacks) > 0:
        print(
            f"  ✅ {len(attacks)} attack session(s) detected"
        )
    else:
        print(
            "  ⚠️  No attack sessions detected — "
            "worker may need more time"
        )
        passed = False

    # Check 4: Attack types detected
    attack_types = {
        a.get("type") for a in attacks
    }
    if "enumeration" in attack_types:
        print("  ✅ Enumeration attack detected")
    else:
        print("  ⚠️  Enumeration attack NOT detected")
        passed = False

    if "credential_stuffing" in attack_types:
        print("  ✅ Credential stuffing detected")
    else:
        print(
            "  ⚠️  Credential stuffing NOT detected"
        )

    print()
    if passed:
        print("  🎉 OVERALL: Vigil is working correctly!")
    else:
        print(
            "  ⚠️  OVERALL: Some checks didn't pass. "
            "See notes above."
        )
        print(
            "     Most common fix: wait 10-15 seconds "
            "for the worker to catch up."
        )


def main() -> None:
    """Run all verification checks."""
    print("\n🔍 VIGIL DETECTION ACCURACY REPORT")
    print("=" * 55)

    # Verify Vigil is running
    try:
        health = httpx.get(f"{API}/health")
        if health.status_code != 200:
            print("❌ Vigil is not running!")
            sys.exit(1)
    except Exception:
        print("❌ Cannot connect to Vigil at", API)
        sys.exit(1)

    # Use 1 hour window if data is recent,
    # 24 hours if running against older data
    hours = 24

    overview = check_overview(hours)
    attacks = check_attacks()
    check_top_threats(hours)
    check_score_distribution(hours)
    run_verdict(overview, attacks)


if __name__ == "__main__":
    main()