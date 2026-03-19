"""
Real client IP extraction from proxy headers.

PRIORITY ORDER:
1. CF-Connecting-IP  → Set by Cloudflare. Can't be spoofed
   because Cloudflare strips any client-set value and replaces
   it with the actual connecting IP.

2. X-Real-IP  → Set by nginx. Trustworthy if your nginx
   is configured correctly.

3. X-Forwarded-For  → The standard header. BUT can be spoofed.
   Take the RIGHTMOST IP that isn't a known trusted proxy.

4. request.client.host  → Direct connection. Only accurate
   if there's no proxy in between.

WHY RIGHTMOST (not leftmost):
X-Forwarded-For: spoofed_by_attacker, real_client, proxy
                  ←───── attacker adds ──→ ←── proxy adds ──→

Proxies APPEND to the right. Attackers can only PREPEND
to the left. So the rightmost non-proxy IP is the real one.

TRUSTED_PROXIES:
IPs we KNOW are our own infrastructure (localhost, etc.)
When scanning right-to-left, we skip these because they're
our proxies, not the client.
"""

from fastapi import Request


# IPs that are known to be our own proxies
# In production, add your load balancer and CDN IPs here
TRUSTED_PROXIES: set[str] = {
    "127.0.0.1",  # IPv4 localhost
    "::1",         # IPv6 localhost
}


def extract_real_ip(request: Request) -> str:
    """
    Extract the real client IP address.

    Goes through headers in priority order.
    Returns "unknown" only if absolutely nothing is available.
    """
    # Priority 1: Cloudflare header (most trustworthy)
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()

    # Priority 2: nginx header
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    # Priority 3: Standard forwarded header
    # Take rightmost untrusted IP
    xff = request.headers.get("x-forwarded-for")
    if xff:
        ips = [ip.strip() for ip in xff.split(",")]
        # Walk from RIGHT to LEFT
        for ip in reversed(ips):
            if ip not in TRUSTED_PROXIES:
                return ip

    # Priority 4: Direct connection
    if request.client:
        return request.client.host

    return "unknown"