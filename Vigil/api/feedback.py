"""
Feedback endpoint for marking detection accuracy.

WHY THIS EXISTS:
Without feedback, we never know our false positive rate.
If Vigil blocks a legitimate user, the admin marks it
as a false positive here. Over time, we track:
- What % of blocks were correct?
- Which attack types have highest false positive rates?
- Are we getting better or worse?

V2: Use accumulated feedback to auto-calibrate scoring
weights. If enumeration detection has 30% false positive
rate, reduce its weight automatically.
"""

import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from Vigil.db.engine import get_db
from Vigil.db.models import Feedback, DEFAULT_ORG_ID

router = APIRouter(
    prefix="/v1/feedback",
    tags=["Feedback"],
)


class FeedbackCreate(BaseModel):
    """
    What the admin submits.

    fingerprint_hash: which fingerprint this is about
    attack_session_id: which attack session (optional)
    verdict: "true_positive", "false_positive", or "unknown"
    notes: optional human notes
    """
    fingerprint_hash: str | None = None
    attack_session_id: str | None = None
    verdict: str  # "true_positive" or "false_positive"
    notes: str | None = None


@router.post("")
async def submit_feedback(
    body: FeedbackCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Record human feedback on a detection.

    This creates a row in the feedback table.
    Dashboard shows "✅ Correct" and "❌ False Positive"
    buttons on each attack session.
    """
    feedback = Feedback(
        org_id=DEFAULT_ORG_ID,
        fingerprint_hash=body.fingerprint_hash,
        attack_session_id=(
            uuid.UUID(body.attack_session_id)
            if body.attack_session_id
            else None
        ),
        verdict=body.verdict,
        notes=body.notes,
    )
    db.add(feedback)
    await db.commit()

    return {
        "status": "recorded",
        "verdict": body.verdict,
    }