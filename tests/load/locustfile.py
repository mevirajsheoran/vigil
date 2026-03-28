"""
Load testing with Locust.

Simulates 3 types of users hitting Vigil simultaneously:
1. Normal users (70%) — browse products, irregular timing
2. Enumeration bots (20%) — sequential IDs, fast + regular
3. Credential stuffers (10%) — rapid login attempts

HOW TO RUN:
  1. Start Vigil API:
     uvicorn Vigil.main:app --port 8000

  2. Start the worker:
     python -m Vigil.workers.stream_consumer

  3. Start Locust:
     locust -f tests/load/locustfile.py --host http://localhost:8000

  4. Open http://localhost:8089 in your browser

  5. Set:
     Number of users: 50
     Spawn rate: 5 (users per second)
     
  6. Click "Start swarming"

  7. Let it run for 2-5 minutes, then stop

  8. Download the HTML report (the download button)
     Save it to docs/load_test_results/

  9. Run verification:
     python scripts/verify_detection.py

WHAT TO LOOK FOR IN RESULTS:
  - Median response time for /v1/analyze should be < 10ms
  - P95 should be < 50ms
  - 0% failure rate for normal users
  - Enumeration bots should start getting blocked after ~30s
  - Check Vigil's /v1/analytics/overview for block rate
"""

import random
import hashlib

from locust import HttpUser, task, between


class NormalUser(HttpUser):
    """
    Simulates a legitimate user browsing a website.

    Characteristics:
    - Visits random pages (products, cart, profile, etc.)
    - Uses a real browser User-Agent with Client Hints
    - Waits 1-5 seconds between requests (thinking time)
    - Occasionally logs in (succeeds)
    - This is 70% of traffic (weight=7)
    """
    wait_time = between(1, 5)
    weight = 7

    def on_start(self):
        """
        Called when this user starts.
        Pick a random browser identity to use
        for all requests from this user.
        """
        browsers = [
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/120.0.0.0",
                '"Chromium";v="120", "Google Chrome";v="120"',
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 Chrome/119.0.0.0",
                '"Chromium";v="119", "Google Chrome";v="119"',
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; "
                "rv:121.0) Gecko/20100101 Firefox/121.0",
                "",  # Firefox doesn't send sec-ch-ua
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/605.1.15 Safari/17.2",
                "",  # Safari doesn't send sec-ch-ua
            ),
        ]
        self.browser_ua, self.sec_ch_ua = random.choice(
            browsers
        )

    @task(10)
    def browse_pages(self):
        """
        Browse product pages — most common user action.

        @task(10) means this task is 10x more likely to
        be chosen than @task(1). Most browsing is just
        looking at products.
        """
        paths = [
            "/api/products",
            "/api/products/featured",
            "/api/products/sale",
            "/api/categories",
            "/api/categories/electronics",
            "/api/cart",
            "/api/profile",
            "/api/orders",
            "/api/wishlist",
            "/api/notifications",
            f"/api/products/{random.randint(1, 100)}",
            f"/api/search?q={random.choice(['laptop', 'phone', 'shoes'])}",
        ]

        headers = {
            "User-Agent": self.browser_ua,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if self.sec_ch_ua:
            headers["sec-ch-ua"] = self.sec_ch_ua

        self.client.post(
            "/v1/analyze",
            json={
                "method": "GET",
                "path": random.choice(paths),
                "status_code": 200,
            },
            headers=headers,
        )

    @task(1)
    def login_success(self):
        """
        Occasional successful login.

        Normal users log in once in a while and succeed.
        This should NOT be flagged as credential stuffing
        because: low frequency, high success rate, same body.
        """
        headers = {
            "User-Agent": self.browser_ua,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if self.sec_ch_ua:
            headers["sec-ch-ua"] = self.sec_ch_ua

        self.client.post(
            "/v1/analyze",
            json={
                "method": "POST",
                "path": "/api/auth/login",
                "status_code": 200,
                "body_hash": "same_user_creds",
            },
            headers=headers,
        )


class EnumerationBot(HttpUser):
    """
    Simulates an attacker scanning for valid user IDs.

    Characteristics:
    - Accesses /api/users/1, /api/users/2, /api/users/3...
    - Uses Python requests library (no sec-ch-ua)
    - Very fast requests (50-150ms between each)
    - Sequential, regular pattern (bot fingerprint)
    - This is 20% of traffic (weight=2)

    WHAT VIGIL SHOULD DO:
    After ~25-30 sequential requests, Vigil's background
    worker should detect the enumeration pattern, raise
    the threat score, and start blocking this fingerprint.
    """
    wait_time = between(0.05, 0.15)
    weight = 2

    def on_start(self):
        """Start scanning from a random ID."""
        self.counter = random.randint(1, 1000)

    @task
    def enumerate_users(self):
        """Scan user IDs sequentially."""
        self.counter += 1
        self.client.post(
            "/v1/analyze",
            json={
                "method": "GET",
                "path": f"/api/users/{self.counter}",
                "status_code": 404,
            },
            headers={
                "User-Agent": "python-requests/2.31.0",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "",
            },
        )


class CredentialStuffer(HttpUser):
    """
    Simulates credential stuffing attack.

    Characteristics:
    - Hits /api/auth/login repeatedly with POST
    - Each request has a UNIQUE body hash (different creds)
    - 90% get 401 (wrong password)
    - Very fast (50-100ms between attempts)
    - Uses automation library (no sec-ch-ua)
    - This is 10% of traffic (weight=1)

    WHAT VIGIL SHOULD DO:
    Detect high concentration of auth POSTs with high
    failure rate and unique body hashes. Score should
    rise and fingerprint should get blocked.
    """
    wait_time = between(0.05, 0.1)
    weight = 1

    @task
    def stuff_credentials(self):
        """Try a random username/password combo."""
        # Generate unique credentials for each attempt
        fake_creds = (
            f"user_{random.randint(1, 1_000_000)}:"
            f"pass_{random.randint(1, 1_000_000)}"
        )
        body_hash = hashlib.sha256(
            fake_creds.encode()
        ).hexdigest()[:16]

        # 90% failure rate
        status = random.choices(
            [401, 200], weights=[9, 1]
        )[0]

        self.client.post(
            "/v1/analyze",
            json={
                "method": "POST",
                "path": "/api/auth/login",
                "status_code": status,
                "body_hash": body_hash,
            },
            headers={
                "User-Agent": "python-requests/2.31.0",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "",
            },
        )