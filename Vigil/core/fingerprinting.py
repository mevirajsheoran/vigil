"""
Server-side device fingerprinting.

WHAT THIS DOES:
Takes 4 HTTP headers that every client sends automatically,
combines them, and hashes them into a 16-character identifier.

WHY THESE 4 HEADERS:

1. User-Agent
   What browser/tool the client is using.
   "Mozilla/5.0 (Windows NT 10.0) Chrome/120" = real browser
   "python-requests/2.31.0" = Python script
   Easy to fake, but most bots don't bother.

2. Accept-Language
   What language the user prefers.
   "en-US,en;q=0.9" = American English
   Set by the browser based on OS settings.
   Attackers rarely think to set this.

3. Accept-Encoding
   What compression the client supports.
   "gzip, deflate, br, zstd" = modern browser
   "gzip, deflate" = Python requests library
   This is set by the HTTP LIBRARY, not the user.
   To change it, you'd need to switch libraries entirely.
   This is the hardest signal to fake.

4. sec-ch-ua (Client Hints)
   Browser version info. Only Chrome/Edge send this.
   '"Chromium";v="120", "Google Chrome";v="120"'
   If User-Agent says "Chrome" but sec-ch-ua is MISSING,
   the User-Agent is likely spoofed by a bot.
   ABSENCE is itself a signal.

WHAT WE DON'T USE:

- Connection: Almost always "keep-alive". Everyone sends
  the same value, so it doesn't help differentiate.

- Accept: Changes based on WHAT you're requesting, not
  WHO is requesting. Same browser sends "text/html" for
  web pages and "application/json" for API calls.
  Using it would split one user into two fingerprints.

COLLISION ANALYSIS:
16 hex chars = 64 bits = 18.4 quintillion possible values.
Birthday problem: 50% collision chance at ~4.3 billion
fingerprints. At our scale (<100K), collision is negligible.
"""

import hashlib
from dataclasses import dataclass

from fastapi import Request


@dataclass
class FingerprintResult:
    """
    Result of fingerprint computation.

    fingerprint_hash: 16-char hex string identifying this client
    confidence: 0.0 to 1.0 — how many signals were present
    signals_used: count of non-empty headers found
    """
    fingerprint_hash: str
    confidence: float
    signals_used: int


def compute_fingerprint(request: Request) -> FingerprintResult:
    """
    Compute a device fingerprint from HTTP headers.

    HOW IT WORKS:
    1. Extract 4 header values (empty string if missing)
    2. Join them with | separator
    3. SHA256 hash the combined string
    4. Take first 16 characters of the hex digest
    5. Count how many signals were present for confidence

    EXAMPLE:
    Headers: User-Agent="Mozilla/5.0", Accept-Language="en-US",
             Accept-Encoding="gzip, deflate, br", sec-ch-ua=""
    Combined: "Mozilla/5.0|en-US|gzip, deflate, br|"
    SHA256:   "a3f8b2c1d9e04f7a..."
    Result:   fingerprint_hash="a3f8b2c1d9e04f7a", confidence=0.75
    """
    # Extract headers (empty string if not present)
    signals = {
        "user_agent": request.headers.get(
            "user-agent", ""
        ),
        "accept_language": request.headers.get(
            "accept-language", ""
        ),
        "accept_encoding": request.headers.get(
            "accept-encoding", ""
        ),
        "sec_ch_ua": request.headers.get(
            "sec-ch-ua", ""
        ),
    }

    # Combine all signals with | separator
    # Order matters — must be consistent every time
    components = [
        signals["user_agent"],
        signals["accept_language"],
        signals["accept_encoding"],
        signals["sec_ch_ua"],
    ]

    raw = "|".join(components)

    # SHA256 hash → take first 16 hex characters
    # SHA256 always produces 64 hex chars. We only need 16
    # for our scale (see collision analysis in docstring)
    fingerprint_hash = hashlib.sha256(
        raw.encode()
    ).hexdigest()[:16]

    # Confidence = what fraction of signals were present
    # 4/4 signals = 1.0 (high confidence)
    # 1/4 signals = 0.25 (low confidence — might be a minimal HTTP client)
    signals_present = sum(
        1 for v in signals.values() if v
    )
    total_signals = len(signals)
    confidence = round(signals_present / total_signals, 2)

    return FingerprintResult(
        fingerprint_hash=fingerprint_hash,
        confidence=confidence,
        signals_used=signals_present,
    )