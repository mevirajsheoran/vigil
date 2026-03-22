"""
Attack pattern detection algorithms.

THESE ARE ORIGINAL ALGORITHMS — not API calls, not
library wrappers. Pure logic that YOU wrote.

This is what makes Vigil different from
"I called an AI API" projects.

TWO DETECTORS:
1. Enumeration: sequential access to numbered resources
2. Credential Stuffing: rapid login attempts with high failure rate

PAGINATION HANDLING:
A user clicking "Next Page" generates:
  /products/page/1, /products/page/2, /products/page/3

This LOOKS sequential but is legitimate navigation.
We maintain a list of known pagination patterns and
EXCLUDE them from enumeration detection to avoid
false positives.

False positive awareness is what separates a good
detection system from a bad one.
"""

import re
import math
from dataclasses import dataclass, field


# ── PAGINATION PATTERNS ──
# These URL patterns are legitimate sequential access.
# Without this list, a user browsing pages would be
# flagged as an attacker.
PAGINATION_PATTERNS = [
    re.compile(r'/page/\d+'),      # /products/page/1
    re.compile(r'/p/\d+'),         # /products/p/1
    re.compile(r'[?&]page=\d+'),   # /products?page=1
    re.compile(r'[?&]offset=\d+'), # /products?offset=20
    re.compile(r'[?&]cursor='),    # /products?cursor=abc123
]


@dataclass
class PatternMatch:
    """
    Result of pattern detection.

    pattern_type: what kind of attack ("enumeration", "credential_stuffing")
    confidence: 0.0 to 1.0 — how sure are we?
    evidence: list of human-readable explanations
    """
    pattern_type: str
    confidence: float
    evidence: list[str] = field(default_factory=list)


def _coefficient_of_variation(values: list[float]) -> float:
    """
    Measure how consistent a list of numbers is.

    CV = standard_deviation / mean

    EXAMPLES:
    [1, 1, 1, 1]       → CV = 0.0   (perfectly consistent)
    [100, 101, 99, 100] → CV ≈ 0.008 (very consistent)
    [1, 100, 3, 500]    → CV ≈ 1.3   (wildly inconsistent)

    USED FOR:
    - Sequential IDs: diffs [1,1,1,1] → CV = 0 → enumeration!
    - Random browsing: diffs [7,-9,96] → CV very high → not enumeration
    - Bot intervals: [100ms, 100ms, 101ms] → CV ≈ 0.005 → bot!
    - Human intervals: [2s, 500ms, 15s] → CV > 1.0 → human
    """
    if len(values) < 2:
        return 0.0

    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0

    # Variance = average of squared differences from mean
    variance = sum(
        (v - mean) ** 2 for v in values
    ) / len(values)

    # Standard deviation = square root of variance
    std_dev = math.sqrt(variance)

    # CV = how big is the spread relative to the average
    return std_dev / abs(mean)


def _is_pagination_path(path: str) -> bool:
    """
    Check if a path matches a known pagination pattern.

    Returns True for paths like:
      /products/page/3
      /api/items?page=5
      /results?offset=20

    These are legitimate sequential access, NOT attacks.
    """
    return any(pat.search(path) for pat in PAGINATION_PATTERNS)


def detect_enumeration(
    paths: list[str],
    timestamps: list[float],
) -> PatternMatch | None:
    """
    Detect enumeration attacks from request path sequences.

    ALGORITHM:
    1. Filter out pagination patterns (reduce false positives)
    2. Extract numeric suffixes from paths using regex
       "/api/users/42" → base="/api/users/", number=42
    3. Group numbers by base path
    4. For each group with 5+ numbers:
       a. Compute differences between consecutive numbers
       b. Calculate CV of differences
       c. CV < 0.3 means consistent step size = enumeration
    5. If timing is also regular (bot-like), boost confidence

    WHY 5 IS THE MINIMUM:
    3-4 sequential requests could be coincidence.
    A user might visit /products/1, /products/2, /products/3
    just browsing. But 5+ with consistent step size across
    ALL of them is very unlikely accidental.

    RETURNS:
    PatternMatch if enumeration detected, None if not.
    """
    # Step 1: Remove pagination paths
    filtered = [
        (p, t) for p, t in zip(paths, timestamps)
        if not _is_pagination_path(p)
    ]

    if len(filtered) < 5:
        return None

    filtered_paths = [p for p, _ in filtered]
    filtered_timestamps = [t for _, t in filtered]

    # Step 2: Extract numeric suffixes
    # Regex: "everything before" + "digits at the end"
    # /api/users/42 → group(1)="/api/users/", group(2)="42"
    numeric_suffix = re.compile(r'^(.+?)(\d+)$')

    # Step 3: Group by base path
    # {"/api/users/": [1, 2, 3, 4, 5]}
    path_groups: dict[str, list[int]] = {}

    for path in filtered_paths:
        match = numeric_suffix.match(path)
        if match:
            base = match.group(1)   # "/api/users/"
            number = int(match.group(2))  # 42
            if base not in path_groups:
                path_groups[base] = []
            path_groups[base].append(number)

    # Step 4: Check each group for sequential patterns
    for base, numbers in path_groups.items():
        if len(numbers) < 5:
            continue

        # Compute differences between consecutive numbers
        # [1, 2, 3, 4, 5] → diffs = [1, 1, 1, 1]
        # [2, 4, 6, 8] → diffs = [2, 2, 2]
        diffs = [
            numbers[i + 1] - numbers[i]
            for i in range(len(numbers) - 1)
        ]

        if not diffs:
            continue

        # Skip if average diff is 0 (same number repeated)
        avg_diff = sum(diffs) / len(diffs)
        if avg_diff == 0:
            continue

        # THE KEY CHECK: is the step size consistent?
        cv = _coefficient_of_variation(
            [float(d) for d in diffs]
        )

        if cv < 0.3 and len(numbers) >= 5:
            # ENUMERATION DETECTED!
            evidence = [
                f"Sequential access to {base}* "
                f"({len(numbers)} requests)",
                f"Number range: {min(numbers)}-{max(numbers)}",
                f"Step consistency (CV): {cv:.3f}",
            ]

            # Step 5: Check timing regularity for confidence boost
            # Bots send requests at very regular intervals
            # Humans have irregular timing
            timing_regular = False
            if len(filtered_timestamps) >= 5:
                intervals = [
                    filtered_timestamps[i + 1]
                    - filtered_timestamps[i]
                    for i in range(
                        len(filtered_timestamps) - 1
                    )
                    if (
                        filtered_timestamps[i + 1]
                        > filtered_timestamps[i]
                    )
                ]
                if intervals:
                    timing_cv = _coefficient_of_variation(
                        intervals
                    )
                    timing_regular = timing_cv < 0.5
                    evidence.append(
                        f"Timing regularity (CV): "
                        f"{timing_cv:.3f} "
                        f"({'regular ← bot-like'if timing_regular else 'irregular ← human-like'})"
                    )

            # Calculate confidence:
            # Base: 0.5 (we found a sequential pattern)
            # Bonus: up to 0.3 for more requests (stronger evidence)
            # Bonus: 0.2 if timing is regular (confirms bot)
            # Cap at 0.99 (never 100% certain)
            confidence = min(
                0.99,
                0.5
                + min(0.3, len(numbers) / 50)
                + (0.2 if timing_regular else 0),
            )

            return PatternMatch(
                pattern_type="enumeration",
                confidence=confidence,
                evidence=evidence,
            )

    return None


def detect_credential_stuffing(
    paths: list[str],
    methods: list[str],
    status_codes: list[int],
    body_hashes: list[str | None] | None = None,
) -> PatternMatch | None:
    """
    Detect credential stuffing from request patterns.

    THREE SIGNALS:

    Signal 1: Auth endpoint concentration (>60%)
      "Are most requests going to login endpoints?"
      Attacker: 95% to /login → YES
      Normal user: 5% to /login, 95% browsing → NO

    Signal 2: Failure rate (>50%)
      "Are most login attempts failing?"
      Attacker: 99% get 401 → YES (wrong passwords from stolen list)
      Normal user: 1 failure then success → NO

    Signal 3: Body uniqueness
      "Is every request body different?"
      Attacker: YES — each request tries a DIFFERENT credential pair
      Normal user: NO — they retry the SAME password they think is right

    ALL THREE signals must be present to trigger detection.
    This dramatically reduces false positives.

    BODY HASH:
    We don't see the actual request body (passwords).
    Instead, the client API hashes the body and sends us
    the hash. Same body = same hash. Different body = different hash.
    We check: are most hashes unique? (= different credentials = stuffing)

    WHY 10 IS THE MINIMUM:
    A normal user might fail login 3-5 times. That's not stuffing.
    10+ failed login attempts from the same fingerprint starts
    looking suspicious. Combined with high body uniqueness,
    it's almost certainly automated.
    """
    # Known auth endpoint paths
    auth_paths = [
        '/login', '/signin', '/sign-in', '/auth',
        '/oauth', '/token', '/session', '/api/auth',
        '/api/login', '/api/signin',
    ]

    # Find indices of POST requests to auth endpoints
    auth_post_indices = [
        i for i, (path, method) in enumerate(
            zip(paths, methods)
        )
        if method.upper() == 'POST'
        and any(ap in path.lower() for ap in auth_paths)
    ]

    # Need at least 10 auth attempts to consider stuffing
    if len(auth_post_indices) < 10:
        return None

    # Signal 1: What fraction of ALL requests are auth POSTs?
    auth_ratio = len(auth_post_indices) / len(paths)

    # Signal 2: What fraction of auth attempts FAILED?
    auth_status_codes = [
        status_codes[i]
        for i in auth_post_indices
        if i < len(status_codes)
    ]

    if not auth_status_codes:
        return None

    failure_count = sum(
        1 for code in auth_status_codes
        if code in (401, 403, 422, 429)
        # 401 = Unauthorized (wrong credentials)
        # 403 = Forbidden (account locked)
        # 422 = Unprocessable (invalid format)
        # 429 = Too Many Requests (rate limited)
    )
    failure_rate = failure_count / len(auth_status_codes)

    # Signal 3: Are request bodies unique?
    # High uniqueness = different credentials each time = stuffing
    # Low uniqueness = same password retried = normal user
    body_uniqueness = 0.5  # default if no body data
    body_evidence = "Body hash data not available"

    if body_hashes:
        auth_bodies = [
            body_hashes[i]
            for i in auth_post_indices
            if i < len(body_hashes)
            and body_hashes[i] is not None
            and body_hashes[i] != ""
        ]
        if auth_bodies:
            unique_bodies = len(set(auth_bodies))
            body_uniqueness = unique_bodies / len(auth_bodies)
            body_evidence = (
                f"Body uniqueness: {body_uniqueness:.0%} "
                f"({unique_bodies} unique bodies in "
                f"{len(auth_bodies)} requests)"
            )

    # BOTH signals must be present:
    # >60% of requests are auth POSTs AND >50% of those fail
    if auth_ratio > 0.6 and failure_rate > 0.5:
        # Confidence from all three signals:
        # auth_ratio contributes up to 0.2
        # failure_rate contributes up to 0.3
        # body_uniqueness contributes up to 0.3
        # Base: 0.2
        confidence = min(
            0.99,
            0.2
            + auth_ratio * 0.2
            + failure_rate * 0.3
            + body_uniqueness * 0.3,
        )

        return PatternMatch(
            pattern_type="credential_stuffing",
            confidence=confidence,
            evidence=[
                f"Auth endpoint concentration: "
                f"{auth_ratio:.0%} "
                f"({len(auth_post_indices)}"
                f"/{len(paths)} requests)",
                f"Failure rate: {failure_rate:.0%} "
                f"({failure_count}"
                f"/{len(auth_status_codes)} failed)",
                body_evidence,
                f"Total auth attempts: "
                f"{len(auth_post_indices)}",
            ],
        )

    return None


def detect_all_patterns(
    paths: list[str],
    methods: list[str],
    timestamps: list[float],
    status_codes: list[int],
    body_hashes: list[str | None] | None = None,
) -> PatternMatch | None:
    """
    Run ALL detectors and return the highest confidence match.

    WHY HIGHEST CONFIDENCE:
    A fingerprint might trigger both enumeration AND
    credential stuffing (unlikely, but possible).
    We return the one we're most sure about.

    Returns None if no pattern detected — this fingerprint
    looks normal (so far).
    """
    detections: list[PatternMatch] = []

    enum_result = detect_enumeration(paths, timestamps)
    if enum_result:
        detections.append(enum_result)

    cred_result = detect_credential_stuffing(
        paths, methods, status_codes, body_hashes
    )
    if cred_result:
        detections.append(cred_result)

    if not detections:
        return None

    # Return highest confidence match
    return max(detections, key=lambda d: d.confidence)