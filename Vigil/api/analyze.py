"""
Core analysis endpoint — POST /v1/analyze

This is the endpoint that businesses integrate into
their API middleware. On every incoming request,
they call this endpoint to ask:
"Should I allow this request?"

FLOW:
1. Receive request (with forwarded headers)
2. Run fast path check (<3ms)
3. Log event to Redis Stream (async, <0.5ms)
4. Return decision to caller
"""

from fastapi import APIRouter, Request
from pydantic import BaseModel

from Vigil.core.fast_path import fast_path_check
from Vigil.core.event_logger import log_request_event

router = APIRouter()


class AnalyzeRequest(BaseModel):
    """
    What the business sends us about each request.

    method: HTTP method of the original request
    path: URL path of the original request
    status_code: response status (if known, for feedback)
    body_hash: hash of request body (for credential stuffing)
    """
    method: str = "GET"
    path: str = "/"
    status_code: int | None = None
    body_hash: str | None = None


class AnalyzeResponse(BaseModel):
    """What we send back."""
    action: str          # "allow", "block", "challenge"
    reason: str          # why this decision was made
    threat_score: float  # 0.0 to 1.0
    fingerprint: str     # 16-char device identifier
    velocity_rpm: int    # current requests per minute
    phase: str           # cold start phase


@router.post(
    "/v1/analyze",
    response_model=AnalyzeResponse,
)
async def analyze_request(
    request: Request,
    body: AnalyzeRequest | None = None,
):
    """
    Analyze a request and return a decision.

    The business's middleware calls this on every request,
    forwarding the original client's HTTP headers so Vigil
    can fingerprint the device.
    """
    # Run fast path check
    result = await fast_path_check(request)

    # Log event to Redis Stream for background processing
    await log_request_event(
        fingerprint_hash=result.fingerprint_hash,
        ip_address=result.ip_address,
        method=body.method if body else request.method,
        path=(
            body.path if body else str(request.url.path)
        ),
        status_code=(
            body.status_code if body else None
        ),
        threat_score=result.threat_score,
        action_taken=result.action,
        body_hash=body.body_hash if body else None,
    )

    return AnalyzeResponse(
        action=result.action,
        reason=result.reason,
        threat_score=result.threat_score,
        fingerprint=result.fingerprint_hash,
        velocity_rpm=result.velocity_rpm,
        phase=result.phase,
    )