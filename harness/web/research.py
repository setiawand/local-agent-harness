from __future__ import annotations

from harness.web.gateway import WebGateway


async def research(gateway: WebGateway, query: str, limit: int = 5) -> list[dict]:
    """Small deterministic research workflow: search only; fetch is explicit per URL.

    Deliberately does not auto-fetch every result. The model can choose relevant
    URLs with separate, journalled WebFetch calls.
    """
    return await gateway.search(query)
