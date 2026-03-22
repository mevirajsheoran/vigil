"""
Tests for attack pattern detection.

TESTING STRATEGY:
- Clear attacks: should be detected with high confidence
- Normal traffic: should NOT be detected (no false positives)
- Edge cases: too few requests, non-numeric paths
- False positive prevention: pagination should be excluded
- Confidence scaling: more evidence = higher confidence

These tests are critical because false positives mean
blocking legitimate users. Every test that checks
"this should NOT be detected" is preventing a real user
from getting wrongly blocked.
"""

from Vigil.core.patterns import (
    detect_enumeration,
    detect_credential_stuffing,
    detect_all_patterns,
    _coefficient_of_variation,
)


# ═══════════════════════════════════════════════════
# COEFFICIENT OF VARIATION TESTS
# ═══════════════════════════════════════════════════

class TestCoefficientOfVariation:
    """Test the CV helper function directly."""

    def test_identical_values_return_zero(self):
        """[5, 5, 5, 5] — no variation at all."""
        assert _coefficient_of_variation(
            [5.0, 5.0, 5.0, 5.0]
        ) == 0.0

    def test_high_variation(self):
        """[1, 100, 1, 100] — wild swings."""
        cv = _coefficient_of_variation(
            [1.0, 100.0, 1.0, 100.0]
        )
        assert cv > 0.8

    def test_low_variation(self):
        """[100, 101, 99, 100] — very consistent."""
        cv = _coefficient_of_variation(
            [100.0, 101.0, 99.0, 100.0]
        )
        assert cv < 0.02

    def test_single_value_returns_zero(self):
        """Can't measure variation with 1 value."""
        assert _coefficient_of_variation([42.0]) == 0.0

    def test_empty_list_returns_zero(self):
        """No values = no variation."""
        assert _coefficient_of_variation([]) == 0.0

    def test_all_zeros_returns_zero(self):
        """Mean is 0, can't divide by 0."""
        assert _coefficient_of_variation(
            [0.0, 0.0, 0.0]
        ) == 0.0


# ═══════════════════════════════════════════════════
# ENUMERATION DETECTION TESTS
# ═══════════════════════════════════════════════════

class TestEnumerationDetection:
    """Test detection of sequential resource access."""

    def test_clear_sequential_access_detected(self):
        """
        /api/users/1, /api/users/2, ... /api/users/20
        This is textbook enumeration. Must be detected.
        """
        paths = [f"/api/users/{i}" for i in range(1, 21)]
        timestamps = [
            1000.0 + i * 0.1 for i in range(20)
        ]
        result = detect_enumeration(paths, timestamps)
        assert result is not None
        assert result.pattern_type == "enumeration"
        assert result.confidence > 0.5

    def test_step_size_2_detected(self):
        """
        /api/users/2, /api/users/4, /api/users/6...
        Even numbers only — still enumeration (step=2).
        """
        paths = [
            f"/api/users/{i}" for i in range(2, 22, 2)
        ]
        timestamps = [
            1000.0 + i * 0.1 for i in range(10)
        ]
        result = detect_enumeration(paths, timestamps)
        assert result is not None

    def test_large_step_detected(self):
        """
        /api/users/100, /api/users/200, /api/users/300...
        Step of 100 — still consistent = enumeration.
        """
        paths = [
            f"/api/users/{i}"
            for i in range(100, 600, 100)
        ]
        timestamps = [
            1000.0 + i * 0.1 for i in range(5)
        ]
        result = detect_enumeration(paths, timestamps)
        assert result is not None

    def test_non_sequential_not_detected(self):
        """
        Random browsing — different paths, no pattern.
        This should NOT trigger enumeration.
        """
        paths = [
            "/api/users/5",
            "/api/products/12",
            "/api/users/5",
            "/about",
            "/api/settings",
            "/api/users/5",
        ]
        timestamps = [
            1000.0, 1005.0, 1008.0,
            1020.0, 1025.0, 1040.0,
        ]
        result = detect_enumeration(paths, timestamps)
        assert result is None

    def test_too_few_requests_not_detected(self):
        """
        Only 3 sequential requests — could be coincidence.
        We need at least 5 to be confident.
        """
        paths = [f"/api/users/{i}" for i in range(1, 4)]
        timestamps = [1000.0, 1000.1, 1000.2]
        result = detect_enumeration(paths, timestamps)
        assert result is None

    def test_non_numeric_paths_ignored(self):
        """
        Paths without numbers can't be enumeration.
        /about, /contact, /pricing — no numbers to sequence.
        """
        paths = [
            "/about", "/contact", "/pricing",
            "/blog", "/faq", "/team",
        ]
        timestamps = [1000.0 + i for i in range(6)]
        result = detect_enumeration(paths, timestamps)
        assert result is None

    def test_pagination_not_detected(self):
        """
        /products/page/1, /products/page/2, /products/page/3
        LOOKS sequential but is legitimate pagination.
        Must NOT be flagged.
        """
        paths = [
            f"/api/products/page/{i}"
            for i in range(1, 21)
        ]
        timestamps = [
            1000.0 + i * 2.0 for i in range(20)
        ]
        result = detect_enumeration(paths, timestamps)
        assert result is None

    def test_query_param_pagination_not_detected(self):
        """
        /api/products?page=1, /api/products?page=2...
        Query parameter pagination — also legitimate.
        """
        paths = [
            f"/api/products?page={i}"
            for i in range(1, 21)
        ]
        timestamps = [
            1000.0 + i * 2.0 for i in range(20)
        ]
        result = detect_enumeration(paths, timestamps)
        assert result is None

    def test_regular_timing_increases_confidence(self):
        """
        Regular timing (bot-like) should give higher
        confidence than irregular timing (human-like)
        for the same path pattern.
        """
        paths = [f"/api/users/{i}" for i in range(1, 21)]

        # Regular timing: exactly 100ms apart
        regular_ts = [
            1000.0 + i * 0.1 for i in range(20)
        ]
        regular_result = detect_enumeration(
            paths, regular_ts
        )

        # Irregular timing: random gaps
        import random
        random.seed(42)
        irregular_ts = sorted([
            1000.0 + random.uniform(0, 60)
            for _ in range(20)
        ])
        irregular_result = detect_enumeration(
            paths, irregular_ts
        )

        assert regular_result is not None
        assert irregular_result is not None
        assert (
            regular_result.confidence
            >= irregular_result.confidence
        )

    def test_evidence_contains_useful_info(self):
        """Evidence should help a human understand WHY."""
        paths = [f"/api/users/{i}" for i in range(1, 21)]
        timestamps = [
            1000.0 + i * 0.1 for i in range(20)
        ]
        result = detect_enumeration(paths, timestamps)
        assert result is not None
        assert len(result.evidence) > 0
        # Should mention the path pattern
        assert any(
            "/api/users/" in e for e in result.evidence
        )


# ═══════════════════════════════════════════════════
# CREDENTIAL STUFFING DETECTION TESTS
# ═══════════════════════════════════════════════════

class TestCredentialStuffingDetection:
    """Test detection of automated login attempts."""

    def test_clear_credential_stuffing_detected(self):
        """
        100 POST /login requests, 90% fail with 401,
        every body is different = textbook stuffing.
        """
        paths = ["/api/auth/login"] * 100
        methods = ["POST"] * 100
        status_codes = [401] * 90 + [200] * 10
        body_hashes = [f"hash_{i}" for i in range(100)]

        result = detect_credential_stuffing(
            paths, methods, status_codes, body_hashes
        )
        assert result is not None
        assert result.pattern_type == "credential_stuffing"
        assert result.confidence > 0.7

    def test_normal_browsing_with_login_not_detected(self):
        """
        Normal user: 3 login attempts among 30 other requests.
        Low auth concentration = NOT stuffing.
        """
        paths = (
            ["/api/auth/login"] * 3
            + ["/api/products"] * 20
            + ["/api/cart"] * 10
        )
        methods = (
            ["POST"] * 3 + ["GET"] * 20 + ["GET"] * 10
        )
        status_codes = [401, 401, 200] + [200] * 30

        result = detect_credential_stuffing(
            paths, methods, status_codes
        )
        assert result is None

    def test_too_few_attempts_not_detected(self):
        """
        5 login attempts — could be a normal user who
        forgot their password. Need 10+ to be suspicious.
        """
        paths = ["/api/auth/login"] * 5
        methods = ["POST"] * 5
        status_codes = [401] * 5

        result = detect_credential_stuffing(
            paths, methods, status_codes
        )
        assert result is None

    def test_high_success_rate_not_detected(self):
        """
        50 login attempts, 90% succeed.
        If most succeed, it's not stuffing — it's a
        legitimate service or SSO integration.
        """
        paths = ["/api/auth/login"] * 50
        methods = ["POST"] * 50
        status_codes = [200] * 45 + [401] * 5

        result = detect_credential_stuffing(
            paths, methods, status_codes
        )
        assert result is None

    def test_get_requests_to_login_not_detected(self):
        """
        GET /login = loading the login page, not attempting login.
        Only POST (actual login submissions) should count.
        """
        paths = ["/api/auth/login"] * 50
        methods = ["GET"] * 50  # Loading page, not submitting
        status_codes = [200] * 50

        result = detect_credential_stuffing(
            paths, methods, status_codes
        )
        assert result is None

    def test_body_uniqueness_increases_confidence(self):
        """
        High body uniqueness (every request has different body)
        should give higher confidence than low uniqueness
        (same body repeated).
        """
        paths = ["/api/auth/login"] * 50
        methods = ["POST"] * 50
        status_codes = [401] * 40 + [200] * 10

        # Every body is different = different credentials
        unique_bodies = [f"hash_{i}" for i in range(50)]
        result_unique = detect_credential_stuffing(
            paths, methods, status_codes, unique_bodies
        )

        # Same body repeated = user retrying same password
        same_bodies = ["same_hash"] * 50
        result_same = detect_credential_stuffing(
            paths, methods, status_codes, same_bodies
        )

        assert result_unique is not None
        if result_same is not None:
            assert (
                result_unique.confidence
                >= result_same.confidence
            )

    def test_evidence_contains_all_signals(self):
        """Evidence should mention all three detection signals."""
        paths = ["/api/auth/login"] * 50
        methods = ["POST"] * 50
        status_codes = [401] * 45 + [200] * 5
        body_hashes = [f"hash_{i}" for i in range(50)]

        result = detect_credential_stuffing(
            paths, methods, status_codes, body_hashes
        )
        assert result is not None

        evidence_text = " ".join(result.evidence)
        assert "concentration" in evidence_text.lower()
        assert "failure" in evidence_text.lower()
        assert "body" in evidence_text.lower()


# ═══════════════════════════════════════════════════
# COMBINED DETECTION TESTS
# ═══════════════════════════════════════════════════

class TestDetectAllPatterns:
    """Test the combined detector."""

    def test_returns_none_for_normal_traffic(self):
        """Everyday browsing should not trigger any detector."""
        paths = [
            "/", "/about", "/products",
            "/products/shoes", "/cart",
        ]
        methods = ["GET"] * 5
        timestamps = [
            1000.0, 1005.0, 1012.0, 1020.0, 1035.0,
        ]
        status_codes = [200] * 5

        result = detect_all_patterns(
            paths, methods, timestamps, status_codes
        )
        assert result is None

    def test_returns_highest_confidence_match(self):
        """
        If both enumeration AND credential stuffing are
        detected, return the one with higher confidence.
        """
        # Mix of enumeration AND credential stuffing
        paths = (
            [f"/api/users/{i}" for i in range(1, 21)]
            + ["/api/auth/login"] * 30
        )
        methods = ["GET"] * 20 + ["POST"] * 30
        timestamps = [
            1000.0 + i * 0.1 for i in range(50)
        ]
        status_codes = (
            [200] * 20 + [401] * 25 + [200] * 5
        )

        result = detect_all_patterns(
            paths, methods, timestamps, status_codes
        )
        assert result is not None
        assert result.confidence > 0.5

    def test_enumeration_detected_through_combined(self):
        """Enumeration should be found via detect_all_patterns."""
        paths = [f"/api/users/{i}" for i in range(1, 21)]
        methods = ["GET"] * 20
        timestamps = [
            1000.0 + i * 0.1 for i in range(20)
        ]
        status_codes = [200] * 20

        result = detect_all_patterns(
            paths, methods, timestamps, status_codes
        )
        assert result is not None
        assert result.pattern_type == "enumeration"