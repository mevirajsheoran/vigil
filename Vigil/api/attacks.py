"""
Attack session endpoints.

Attack sessions are created by the background worker when
pattern detection confirms suspicious activity (confidence > 0.7).
Each session groups related requests and includes AI analysis.

The dashboard shows these as alert cards with severity colors
and AI-generated explanations.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from Vigil.db.engine import get_db
from Vigil.db.models import AttackSession

router = APIRouter(
    prefix="/v1/attacks",
    tags=["Attacks"],
)


@router.get("")
async def list_attacks(
    limit: int = 20,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    List attack sessions, newest first.

    Optional filter by status:
    - "active" = ongoing attack
    - "mitigated" = blocked by Vigil
    - "resolved" = manually marked as resolved
    - "false_positive" = incorrectly detected

    Uses SQLAlchemy ORM query instead of raw SQL because
    this is a simple query. Complex analytics use raw SQL
    (see analytics.py).
    """
    query = (
        select(AttackSession)
        .order_by(desc(AttackSession.created_at))
        .limit(limit)
    )

    if status:
        query = query.where(
            AttackSession.status == status
        )

    result = await db.execute(query)
    attacks = result.scalars().all()

    return [
        {
            "id": str(a.id),
            "fingerprint_hash": a.fingerprint_hash,
            "type": a.attack_type,
            "severity": a.severity,
            "status": a.status,
            "total_requests": a.total_requests,
            "total_ips": a.total_ips,
            "started_at": (
                a.started_at.isoformat()
                if a.started_at
                else None
            ),
            "ai_confidence": a.ai_confidence,
            "ai_explanation": a.ai_explanation,
            "created_at": (
                a.created_at.isoformat()
                if a.created_at
                else None
            ),
        }
        for a in attacks
    ]