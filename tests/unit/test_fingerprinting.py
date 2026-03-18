"""
Tests for fingerprint computation.

TESTING STRATEGY:
- Determinism: same input always produces same output
- Differentiation: different inputs produce different outputs
- Edge cases: missing headers, empty headers
- Properties: correct length, valid hex, confidence scaling
- Security: spoofed Chrome without Client Hints detected

We use MagicMock to create fake FastAPI Request objects.
This lets us test fingerprinting WITHOUT running a server.
"""

from unittest.mock import MagicMock

from Vigil.core.fingerprinting import (
    compute_fingerprint,
    FingerprintResult,
)


def _make_request(headers: dict) -> MagicMock:
    """
    Helper: create a fake FastAPI Request with given headers.

    MagicMock creates a fake object that behaves like
    a real Request. We only need the .headers attribute,
    so we set just that.
    """
    mock = MagicMock()
    mock.headers = headers
    return mock


class TestFingerprintDeterminism:
    """Same inputs should always produce same outputs."""

    def test_identical_headers_produce_identical_fingerprint(
        self,
    ):
        """
        THE MOST IMPORTANT TEST.
        If fingerprinting isn't deterministic, nothing works.
        Same client = same fingerprint. Every time.
        """
        headers = {
            "user-agent": "Mozilla/5.0",
            "accept-language": "en-US",
            "accept-encoding": "gzip, deflate",
            "sec-ch-ua": '"Chromium";v="120"',
        }
        r1 = compute_fingerprint(_make_request(headers))
        r2 = compute_fingerprint(_make_request(headers))
        assert r1.fingerprint_hash == r2.fingerprint_hash

    def test_repeated_calls_same_result(self):
        """Run 100 times — should be identical every time."""
        headers = {"user-agent": "TestBot/1.0"}
        first = compute_fingerprint(
            _make_request(headers)
        ).fingerprint_hash

        for _ in range(100):
            result = compute_fingerprint(
                _make_request(headers)
            )
            assert result.fingerprint_hash == first


class TestFingerprintDifferentiation:
    """Different inputs should produce different outputs."""

    def test_different_user_agent(self):
        """Different browser = different fingerprint."""
        h1 = {
            "user-agent": "Mozilla/5.0",
            "accept-language": "en-US",
            "accept-encoding": "gzip",
            "sec-ch-ua": "",
        }
        h2 = {**h1, "user-agent": "Python-requests/2.31"}

        r1 = compute_fingerprint(_make_request(h1))
        r2 = compute_fingerprint(_make_request(h2))
        assert r1.fingerprint_hash != r2.fingerprint_hash

    def test_different_accept_encoding(self):
        """
        Different compression support = different fingerprint.
        This is the hardest signal to fake because it's
        set by the HTTP library, not the user.
        """
        h1 = {
            "user-agent": "Mozilla/5.0",
            "accept-encoding": "gzip, deflate, br",
        }
        h2 = {
            "user-agent": "Mozilla/5.0",
            "accept-encoding": "gzip, deflate",
        }
        r1 = compute_fingerprint(_make_request(h1))
        r2 = compute_fingerprint(_make_request(h2))
        assert r1.fingerprint_hash != r2.fingerprint_hash

    def test_different_language(self):
        """Different language preferences = different fingerprint."""
        h1 = {"user-agent": "Bot", "accept-language": "en-US"}
        h2 = {"user-agent": "Bot", "accept-language": "fr-FR"}

        r1 = compute_fingerprint(_make_request(h1))
        r2 = compute_fingerprint(_make_request(h2))
        assert r1.fingerprint_hash != r2.fingerprint_hash

    def test_chrome_with_vs_without_client_hints(self):
        """
        Chrome User-Agent WITH sec-ch-ua vs WITHOUT.
        Real Chrome always sends sec-ch-ua.
        If User-Agent says "Chrome" but sec-ch-ua is
        missing, the UA is likely spoofed by a bot.
        The fingerprint should be DIFFERENT.
        """
        real_chrome = {
            "user-agent": "Mozilla/5.0 Chrome/120",
            "accept-language": "en-US",
            "accept-encoding": "gzip, deflate, br",
            "sec-ch-ua": '"Chromium";v="120"',
        }
        fake_chrome = {
            "user-agent": "Mozilla/5.0 Chrome/120",
            "accept-language": "en-US",
            "accept-encoding": "gzip, deflate, br",
            "sec-ch-ua": "",  # Missing! Bot pretending to be Chrome
        }
        r1 = compute_fingerprint(_make_request(real_chrome))
        r2 = compute_fingerprint(_make_request(fake_chrome))
        assert r1.fingerprint_hash != r2.fingerprint_hash


class TestFingerprintEdgeCases:
    """Handle unusual inputs without crashing."""

    def test_empty_headers_dont_crash(self):
        """No headers at all — should still produce a fingerprint."""
        result = compute_fingerprint(_make_request({}))
        assert isinstance(result, FingerprintResult)
        assert len(result.fingerprint_hash) == 16
        assert result.confidence == 0.0
        assert result.signals_used == 0

    def test_partial_headers(self):
        """Only some headers present — should work fine."""
        headers = {"user-agent": "SomeBot/1.0"}
        result = compute_fingerprint(_make_request(headers))
        assert len(result.fingerprint_hash) == 16
        assert result.signals_used == 1

    def test_very_long_user_agent(self):
        """Some bots send absurdly long User-Agents."""
        headers = {"user-agent": "A" * 10000}
        result = compute_fingerprint(_make_request(headers))
        assert len(result.fingerprint_hash) == 16


class TestFingerprintProperties:
    """Verify output format and confidence scoring."""

    def test_fingerprint_is_16_characters(self):
        headers = {"user-agent": "anything"}
        result = compute_fingerprint(_make_request(headers))
        assert len(result.fingerprint_hash) == 16

    def test_fingerprint_is_valid_hex(self):
        """Should be a valid hexadecimal string."""
        headers = {"user-agent": "test"}
        result = compute_fingerprint(_make_request(headers))
        # int() with base 16 raises ValueError if not valid hex
        int(result.fingerprint_hash, 16)

    def test_confidence_zero_with_no_signals(self):
        result = compute_fingerprint(_make_request({}))
        assert result.confidence == 0.0

    def test_confidence_one_with_all_signals(self):
        headers = {
            "user-agent": "Bot",
            "accept-language": "en",
            "accept-encoding": "gzip",
            "sec-ch-ua": '"Chrome"',
        }
        result = compute_fingerprint(_make_request(headers))
        assert result.confidence == 1.0

    def test_confidence_scales_with_signal_count(self):
        """More headers present = higher confidence."""
        few = {"user-agent": "Bot"}
        many = {
            "user-agent": "Bot",
            "accept-language": "en",
            "accept-encoding": "gzip",
            "sec-ch-ua": '"Chrome"',
        }
        r_few = compute_fingerprint(_make_request(few))
        r_many = compute_fingerprint(_make_request(many))
        assert r_many.confidence > r_few.confidence