"""
Tests for real IP extraction from proxy headers.

TESTING STRATEGY:
- Priority: Cloudflare > X-Real-IP > X-Forwarded-For > direct
- Security: XFF spoofing should take rightmost untrusted IP
- Edge cases: whitespace, missing headers, no client
"""

from unittest.mock import MagicMock

from Vigil.core.ip_extraction import extract_real_ip


def _make_request(
    headers: dict,
    client_host: str = "127.0.0.1",
) -> MagicMock:
    """Create a fake Request with headers and client IP."""
    mock = MagicMock()
    mock.headers = headers
    mock.client.host = client_host
    return mock


class TestCloudflareHeader:
    """CF-Connecting-IP should take highest priority."""

    def test_cloudflare_header_wins_over_everything(self):
        """Even if other headers exist, CF header wins."""
        headers = {
            "cf-connecting-ip": "1.1.1.1",
            "x-real-ip": "2.2.2.2",
            "x-forwarded-for": "3.3.3.3",
        }
        assert extract_real_ip(
            _make_request(headers)
        ) == "1.1.1.1"

    def test_cloudflare_header_stripped(self):
        """Whitespace around the IP should be removed."""
        headers = {"cf-connecting-ip": "  1.1.1.1  "}
        assert extract_real_ip(
            _make_request(headers)
        ) == "1.1.1.1"


class TestXRealIpHeader:
    """X-Real-IP used when no Cloudflare header."""

    def test_x_real_ip_used_when_no_cf(self):
        headers = {"x-real-ip": "3.3.3.3"}
        assert extract_real_ip(
            _make_request(headers)
        ) == "3.3.3.3"

    def test_x_real_ip_not_used_when_cf_exists(self):
        headers = {
            "cf-connecting-ip": "1.1.1.1",
            "x-real-ip": "2.2.2.2",
        }
        result = extract_real_ip(_make_request(headers))
        assert result == "1.1.1.1"  # CF wins


class TestXForwardedFor:
    """X-Forwarded-For: rightmost untrusted IP."""

    def test_rightmost_untrusted_ip_selected(self):
        """
        XFF: spoofed, real_client, trusted_proxy
        Should return real_client (5.6.7.8), not spoofed.
        """
        headers = {
            "x-forwarded-for": "1.2.3.4, 5.6.7.8, 127.0.0.1"
        }
        result = extract_real_ip(_make_request(headers))
        assert result == "5.6.7.8"

    def test_single_ip_in_xff(self):
        headers = {"x-forwarded-for": "9.8.7.6"}
        assert extract_real_ip(
            _make_request(headers)
        ) == "9.8.7.6"

    def test_all_trusted_proxies_falls_through(self):
        """If ALL IPs in XFF are trusted, fall to client.host."""
        headers = {
            "x-forwarded-for": "127.0.0.1, ::1"
        }
        result = extract_real_ip(
            _make_request(headers, client_host="10.0.0.1")
        )
        assert result == "10.0.0.1"

    def test_whitespace_stripped_from_xff(self):
        headers = {
            "x-forwarded-for": " 1.2.3.4 , 5.6.7.8 "
        }
        result = extract_real_ip(_make_request(headers))
        assert result == "5.6.7.8"


class TestDirectConnection:
    """Fallback to request.client.host."""

    def test_direct_connection_used_when_no_headers(self):
        headers = {}
        result = extract_real_ip(
            _make_request(headers, client_host="10.0.0.1")
        )
        assert result == "10.0.0.1"

    def test_no_client_returns_unknown(self):
        """If there's no client info at all."""
        mock = MagicMock()
        mock.headers = {}
        mock.client = None
        assert extract_real_ip(mock) == "unknown"