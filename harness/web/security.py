from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

import aiohttp


class WebSecurityError(ValueError):
    pass


def normalize_url(raw_url: str, allowed_schemes: set[str] | None = None) -> tuple[str, str, int]:
    if not isinstance(raw_url, str) or len(raw_url) > 4096:
        raise WebSecurityError("URL is missing or exceeds 4096 characters.")
    parsed = urlsplit(raw_url.strip())
    allowed_schemes = allowed_schemes or {"http", "https"}\n    if parsed.scheme.lower() not in allowed_schemes:
        raise WebSecurityError("Only HTTP and HTTPS URLs are permitted.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise WebSecurityError("URL host is missing or URL credentials are forbidden.")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal", ".test")):
        raise WebSecurityError("Local and internal hostnames are blocked.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise WebSecurityError("IP-literal URLs are blocked.")
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if not 1 <= port <= 65535:
        raise WebSecurityError("Invalid URL port.")
    clean = urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))
    return clean, host, port


async def resolve_public(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise WebSecurityError(f"DNS resolution failed: {exc}") from exc
    addresses = sorted({item[4][0] for item in infos})
    if not addresses:
        raise WebSecurityError("Hostname resolved to no addresses.")
    for value in addresses:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
        if not ip.is_global:
            raise WebSecurityError(f"Host resolves to a non-public address ({ip}).")
    return addresses


class PinnedPublicResolver(aiohttp.abc.AbstractResolver):
    """Resolve once through the policy, then give vetted IPs to aiohttp's connector."""

    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        addresses = await resolve_public(host, port)
        return [
            {
                "hostname": host, "host": address, "port": port,
                "family": socket.AF_INET6 if ":" in address else socket.AF_INET,
                "proto": 0, "flags": 0,
            }
            for address in addresses
        ]

    async def close(self):
        return None


async def validate_public_target(url: str) -> tuple[str, str, int]:
    clean, host, port = normalize_url(url)
    await resolve_public(host, port)
    return clean, host, port
