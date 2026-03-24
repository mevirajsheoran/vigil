"""
Decision engine — what HTTP response to send for each action.

FOUR ACTIONS:

ALLOW (200): Normal traffic. Let through.
  The protected API handles the request normally.

CHALLENGE (429): Soft block with Retry-After header.
  Legitimate users wait 30 seconds and retry successfully.
  Bots usually give up or don't understand Retry-After.
  This is a middle ground — not sure if attack or not.

BLOCK (403): Hard block. Confirmed threats.
  "You are not allowed to access this resource."
  Used for high-confidence detections.

SHADOWBAN (200 with fake data): Sneaky response.
  The scraper thinks it succeeded but gets garbage data.
  It doesn't adapt its strategy because it doesn't
  know it's been detected. Very effective against
  automated scrapers that check for non-200 status codes.
"""

import random
from dataclasses import dataclass


@dataclass
class Decision:
    """
    What to send back to the client.

    action: which action we're taking
    status_code: HTTP status code
    body: JSON response body (None for allow)
    headers: extra HTTP headers to include
    reason: why this decision was made (for logging)
    """
    action: str
    status_code: int
    body: dict | None
    headers: dict
    reason: str


def make_decision(
    action: str,
    reason: str,
    original_path: str = "/",
    shadowban_enabled: bool = False,
) -> Decision:
    """
    Create an HTTP response decision based on the action.

    Called by the analyze endpoint after fast_path_check
    determines what action to take.
    """
    if action == "allow":
        return Decision(
            action="allow",
            status_code=200,
            body=None,
            headers={},
            reason=reason,
        )

    elif action == "challenge":
        return Decision(
            action="challenge",
            status_code=429,
            body={
                "error": "too_many_requests",
                "message": (
                    "Rate limit exceeded. "
                    "Please retry after a moment."
                ),
                "retry_after": 30,
            },
            headers={"Retry-After": "30"},
            reason=reason,
        )

    elif action == "block":
        return Decision(
            action="block",
            status_code=403,
            body={
                "error": "forbidden",
                "message": "Access denied.",
            },
            headers={},
            reason=reason,
        )

    elif action == "shadowban" and shadowban_enabled:
        return Decision(
            action="shadowban",
            status_code=200,
            body=_generate_fake_data(original_path),
            headers={},
            reason=reason,
        )

    else:
        # Unknown action → default to block (safe choice)
        return Decision(
            action="block",
            status_code=403,
            body={"error": "forbidden"},
            headers={},
            reason=reason,
        )


def _generate_fake_data(path: str) -> dict:
    """
    Generate plausible-looking fake data for shadowbanned scrapers.

    The data looks real enough that the scraper doesn't
    realize it's being fed garbage. It continues scraping
    without adapting.
    """
    fake_names = [
        "John Smith", "Jane Doe", "Bob Wilson",
        "Alice Johnson", "Charlie Brown",
    ]
    fake_emails = [
        "user@example.com", "test@test.com",
        "sample@demo.org",
    ]

    if "user" in path.lower():
        return {
            "id": random.randint(10000, 99999),
            "name": random.choice(fake_names),
            "email": random.choice(fake_emails),
            "created_at": "2024-01-01T00:00:00Z",
        }
    elif "product" in path.lower():
        return {
            "id": random.randint(10000, 99999),
            "name": f"Product {random.randint(1, 999)}",
            "price": round(
                random.uniform(9.99, 999.99), 2
            ),
            "in_stock": random.choice([True, False]),
        }
    else:
        return {
            "id": random.randint(10000, 99999),
            "data": "sample_data",
            "status": "ok",
        }