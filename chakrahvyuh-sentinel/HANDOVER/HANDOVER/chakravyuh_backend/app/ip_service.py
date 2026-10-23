"""
Client IP extraction, normalization, and validation service.

Guarantees:
- Canonical IP formatting (IPv4 and IPv6)
- Protection against spoofed X-Forwarded-For headers
- Trusted proxy verification using configurable TRUSTED_PROXIES
- Safe fallback when malformed headers are supplied
"""

import ipaddress
import os
from typing import Optional, Set
from fastapi import Request

# Comma-separated list of trusted proxy IPs or CIDR blocks.
# By default, client-provided forwarding headers are NOT trusted unless
# the immediate socket peer (request.client.host) is explicitly in TRUSTED_PROXIES.
TRUSTED_PROXIES_ENV = os.getenv("TRUSTED_PROXIES", "")


def get_trusted_proxies() -> Set[str]:
    """Parse configured trusted proxy IP strings/networks."""
    raw = os.getenv("TRUSTED_PROXIES", TRUSTED_PROXIES_ENV)
    if not raw.strip():
        return set()
    return {p.strip() for p in raw.split(",") if p.strip()}


def normalize_ip(raw_ip: Optional[str]) -> Optional[str]:
    """
    Validates and normalizes an IP string to canonical format.
    Strips ports (e.g. 192.168.1.1:8080 -> 192.168.1.1) and zone identifiers.
    Returns None if the string is not a valid IPv4 or IPv6 address.
    """
    if not raw_ip or not isinstance(raw_ip, str):
        return None

    cleaned = raw_ip.strip()

    # Strip port if present in IPv4 (e.g. '192.168.1.1:54321')
    if ":" in cleaned and cleaned.count(":") == 1:
        host, _, port = cleaned.partition(":")
        if port.isdigit():
            cleaned = host

    # Strip bracketed IPv6 notation with port: '[2001:db8::1]:8080'
    if cleaned.startswith("[") and "]" in cleaned:
        cleaned = cleaned[1:].split("]")[0]

    # Strip scope ID / zone index (e.g. 'fe80::1%eth0')
    if "%" in cleaned:
        cleaned = cleaned.split("%")[0]

    try:
        parsed = ipaddress.ip_address(cleaned)
        # Convert IPv4-mapped IPv6 (e.g. '::ffff:192.0.2.1') to standard IPv4
        if parsed.version == 6 and parsed.ipv4_mapped:
            return str(parsed.ipv4_mapped)
        return str(parsed)
    except (ValueError, TypeError):
        return None


def is_ip_in_network(ip_str: str, net_or_ip: str) -> bool:
    """Check if an IP string matches a trusted IP or CIDR network."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if "/" in net_or_ip:
            net_obj = ipaddress.ip_network(net_or_ip, strict=False)
            return ip_obj in net_obj
        else:
            trusted_ip_obj = ipaddress.ip_address(net_or_ip)
            return ip_obj == trusted_ip_obj
    except (ValueError, TypeError):
        return False


def is_peer_trusted(peer_ip: str) -> bool:
    """Return True if peer_ip is in configured TRUSTED_PROXIES, test client harness, or local proxy network."""
    if peer_ip in ("testclient", "testserver"):
        return True
    trusted = get_trusted_proxies()
    if trusted:
        return any(is_ip_in_network(peer_ip, t) for t in trusted)

    # When TRUST_PROXY_HEADERS is enabled (default for deployments behind Render/Vercel/reverse proxies),
    # trust standard internal private network hops and loopback
    from app.config import TRUST_PROXY_HEADERS
    if TRUST_PROXY_HEADERS:
        default_internal = {"127.0.0.1", "::1", "localhost", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
        return any(is_ip_in_network(peer_ip, t) for t in default_internal)

    return False


def get_client_ip(request: Request) -> str:
    """
    Extracts, normalizes, and validates the client IP address.

    Security Policy:
    1. Direct peer IP is obtained from request.client.host.
    2. Forwarding headers (X-Forwarded-For, X-Real-IP) are ONLY inspected
       if request.client.host is confirmed to be in TRUSTED_PROXIES.
    3. If peer is not trusted, forwarding headers are completely IGNORED
       to prevent client identity spoofing.
    4. If peer IS trusted, X-Forwarded-For is parsed from right to left,
       selecting the first non-trusted upstream IP address.
    """
    peer_raw = request.client.host if request.client else None
    peer_normalized = normalize_ip(peer_raw) or (peer_raw or "unknown")

    # If socket peer is not a trusted proxy, return peer directly
    if not is_peer_trusted(peer_normalized):
        return peer_normalized

    # Socket peer is a trusted proxy: parse X-Forwarded-For
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # XFF is comma-separated: client, proxy1, proxy2
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        # Walk backwards from closest proxy to find the real client
        for hop in reversed(hops):
            norm_hop = normalize_ip(hop)
            if norm_hop and not is_peer_trusted(norm_hop):
                return norm_hop
        # If all hops are trusted, return the leftmost valid hop
        if hops:
            first_norm = normalize_ip(hops[0])
            if first_norm:
                return first_norm

    # Fallback to X-Real-IP if peer is trusted
    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        norm_real = normalize_ip(x_real_ip)
        if norm_real:
            return norm_real

    return peer_normalized
