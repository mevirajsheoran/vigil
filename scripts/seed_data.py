"""
Generate demo data for dashboard and analytics testing.

Creates three types of traffic:
1. Normal users browsing products (500 requests)
2. Enumeration attacker scanning user IDs (100 requests)
3. Credential stuffer hitting login (80 requests)

USAGE:
  Make sure Vigil API and worker are running, then:
    python scripts/seed_data.py

  Wait 10 seconds after it finishes for the worker
  to process all events, then check:
    http://localhost:8000/v1/analytics/overview?hours=1
    http://localhost:8000/v1/attacks
"""

import asyncio
import random
import hashlib
import time
import sys

import httpx

API = "http://localhost:8000"


async def send_request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    user_agent: str,
    accept_encoding: str = "gzip, deflate, br",
    accept_language: str = "en-US,en;q=0.9",
    sec_ch_ua: str = "",
    status_code: int | None = None,
    body_hash: str | None = None,
) -> dict | None:
    """
    Send one request to Vigil's /v1/analyze endpoint.

    Returns the response dict or None if the request failed.
    """
    try:
        payload: dict = {
            "method": method,
            "path": path,
        }
        if status_code is not None:
            payload["status_code"] = status_code
        if body_hash is not None:
            payload["body_hash"] = body_hash

        response = await client.post(
            f"{API}/v1/analyze",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": user_agent,
                "Accept-Encoding": accept_encoding,
                "Accept-Language": accept_language,
                "sec-ch-ua": sec_ch_ua,
            },
        )
        return response.json()
    except Exception as e:
        print(f"  Error: {e}")
        return None


async def seed_normal_traffic(
    client: httpx.AsyncClient,
) -> None:
    """
    Simulate 500 requests from normal users.

    Normal users:
    - Browse different pages (products, cart, profile)
    - Use real browser User-Agents
    - Have sec-ch-ua (Chrome Client Hints)
    - Request at irregular intervals
    """
    print("\n📦 Seeding normal traffic (500 requests)...")

    normal_paths = [
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
        "/api/search?q=laptop",
        "/api/search?q=headphones",
        "/api/products/reviews",
        "/about",
        "/contact",
    ]

    # 10 different "normal users" with different browsers
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
        "Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 Safari/17.2",
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
        "AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) "
        "AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Edg/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
    ]

    for i in range(500):
        ua = user_agents[i % len(user_agents)]
        path = random.choice(normal_paths)

        # Chrome browsers send sec-ch-ua
        sec_ch_ua = ""
        if "Chrome" in ua:
            sec_ch_ua = '"Chromium";v="120", "Google Chrome";v="120"'

        await send_request(
            client=client,
            method="GET",
            path=path,
            user_agent=ua,
            accept_encoding="gzip, deflate, br, zstd",
            accept_language="en-US,en;q=0.9",
            sec_ch_ua=sec_ch_ua,
            status_code=200,
        )

        if i % 100 == 0:
            print(f"  Normal: {i}/500")

        # Small random delay to simulate real browsing
        if i % 10 == 0:
            await asyncio.sleep(0.05)

    print("  ✅ Normal traffic: 500 requests sent")


async def seed_enumeration_attack(
    client: httpx.AsyncClient,
) -> None:
    """
    Simulate an enumeration attack: sequential user ID scanning.

    Attacker characteristics:
    - Python requests library (no sec-ch-ua)
    - Sequential paths: /api/users/1, /api/users/2, ...
    - Regular timing (bot-like)
    - accept-encoding: "gzip, deflate" (Python default)
    """
    print("\n🔴 Seeding enumeration attack (100 requests)...")

    for i in range(1, 101):
        await send_request(
            client=client,
            method="GET",
            path=f"/api/users/{i}",
            user_agent="python-requests/2.31.0",
            accept_encoding="gzip, deflate",
            accept_language="",
            sec_ch_ua="",
            status_code=200 if i <= 3 else 404,
        )

        if i % 25 == 0:
            print(f"  Enum: {i}/100")

        # Very fast, regular intervals (bot-like)
        await asyncio.sleep(0.02)

    print("  ✅ Enumeration attack: 100 requests sent")


async def seed_credential_stuffing(
    client: httpx.AsyncClient,
) -> None:
    """
    Simulate credential stuffing: rapid login attempts
    with different credentials.

    Attacker characteristics:
    - Hits /api/auth/login repeatedly with POST
    - Each request has a unique body hash (different creds)
    - 90% get 401 (wrong password), 10% get 200 (lucky hit)
    - Uses automation library (no sec-ch-ua)
    """
    print(
        "\n🔴 Seeding credential stuffing attack "
        "(80 requests)..."
    )

    for i in range(80):
        # Each attempt has unique credentials
        fake_creds = f"user_{random.randint(1, 999999)}:pass_{random.randint(1, 999999)}"
        body_hash = hashlib.sha256(
            fake_creds.encode()
        ).hexdigest()[:16]

        # 90% fail, 10% succeed
        status = random.choices(
            [401, 200], weights=[9, 1]
        )[0]

        await send_request(
            client=client,
            method="POST",
            path="/api/auth/login",
            user_agent="python-requests/2.31.0",
            accept_encoding="gzip, deflate",
            accept_language="",
            sec_ch_ua="",
            status_code=status,
            body_hash=body_hash,
        )

        if i % 20 == 0:
            print(f"  Cred stuff: {i}/80")

        await asyncio.sleep(0.02)

    print("  ✅ Credential stuffing: 80 requests sent")


async def check_results(
    client: httpx.AsyncClient,
) -> None:
    """Check what Vigil detected after processing."""
    print("\n⏳ Waiting 10 seconds for worker to process...")
    await asyncio.sleep(10)

    print("\n📊 RESULTS:")
    print("=" * 50)

    # Overview
    try:
        response = await client.get(
            f"{API}/v1/analytics/overview",
            params={"hours": 1},
        )
        overview = response.json()
        print(f"Total requests:     {overview.get('total_requests', 0):,}")
        print(f"Allowed:            {overview.get('allowed', 0):,}")
        print(f"Blocked:            {overview.get('blocked', 0):,}")
        print(f"Challenged:         {overview.get('challenged', 0):,}")
        print(f"Block rate:         {overview.get('block_rate_pct', 0)}%")
        print(f"Unique fingerprints:{overview.get('unique_fingerprints', 0)}")
        print(f"Avg threat score:   {overview.get('avg_threat_score', 0)}")
    except Exception as e:
        print(f"  Failed to get overview: {e}")

    # Attacks
    print(f"\n{'=' * 50}")
    try:
        response = await client.get(
            f"{API}/v1/attacks",
            params={"limit": 10},
        )
        attacks = response.json()
        print(f"Attack sessions detected: {len(attacks)}")
        for attack in attacks[:5]:
            print(
                f"  - {attack.get('type', '?')} | "
                f"severity: {attack.get('severity', '?')} | "
                f"requests: {attack.get('total_requests', '?')} | "
                f"AI: {(attack.get('ai_explanation') or 'no analysis')[:80]}"
            )
    except Exception as e:
        print(f"  Failed to get attacks: {e}")

    # Top threats
    print(f"\n{'=' * 50}")
    try:
        response = await client.get(
            f"{API}/v1/analytics/top-threats",
            params={"hours": 1},
        )
        threats = response.json()
        print(f"Top threatening fingerprints: {len(threats)}")
        for t in threats[:3]:
            print(
                f"  - {t.get('fingerprint_hash', '?')[:16]} | "
                f"score: {t.get('avg_threat_score', '?')} | "
                f"requests: {t.get('total_requests', '?')} | "
                f"IPs: {t.get('distinct_ips', '?')}"
            )
    except Exception as e:
        print(f"  Failed to get threats: {e}")


async def main() -> None:
    """Run the full seeding pipeline."""
    print("🚀 Vigil Seed Data Generator")
    print("=" * 50)
    print(f"Target: {API}")

    # Verify Vigil is running
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            health = await client.get(f"{API}/health")
            if health.status_code != 200:
                print("❌ Vigil is not running!")
                print(
                    "   Start it with: "
                    "uvicorn Vigil.main:app --port 8000"
                )
                sys.exit(1)
            print("✅ Vigil is running")
        except Exception:
            print("❌ Cannot connect to Vigil!")
            print(
                "   Start it with: "
                "uvicorn Vigil.main:app --port 8000"
            )
            sys.exit(1)

        # Make sure worker is running
        print(
            "\n⚠️  Make sure the worker is running in "
            "another terminal:"
        )
        print(
            "   python -m Vigil.workers.stream_consumer"
        )
        print()

        start = time.time()

        await seed_normal_traffic(client)
        await seed_enumeration_attack(client)
        await seed_credential_stuffing(client)
        await check_results(client)

        elapsed = time.time() - start
        print(f"\n⏱️  Total time: {elapsed:.1f} seconds")
        print(
            "\n🎉 Done! Check the dashboard or Swagger UI:"
        )
        print(f"   Swagger: {API}/docs")
        print(
            f"   Overview: "
            f"{API}/v1/analytics/overview?hours=1"
        )
        print(f"   Attacks: {API}/v1/attacks")


if __name__ == "__main__":
    asyncio.run(main())