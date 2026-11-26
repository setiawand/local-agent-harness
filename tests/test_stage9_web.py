from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from harness.config import load_config
from harness.security import SecurityPolicy, SecurityViolation
from harness.web.citations import CitationStore
from harness.web.security import WebSecurityError, normalize_url, resolve_public


def test_web_config_defaults_disabled_and_accepts_loopback_searxng(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        '[harness]\nendpoint = "http://127.0.0.1:8001"\n'
        '[web]\nenabled = true\n'
        '[web.searxng]\nbase_url = "http://127.0.0.1:8888"\n',
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.web.enabled is True
    assert config.web.base_url == "http://127.0.0.1:8888"
    assert config.web.max_results == 5


def test_web_config_rejects_non_loopback_search_provider(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        '[harness]\n'
        '[web]\nenabled = true\n'
        '[web.searxng]\nbase_url = "http://192.168.1.10:8888"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="loopback"):
        load_config(path)


def test_web_config_cannot_disable_ssrf_protections(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        '[harness]\n[web]\nenabled = true\n'
        '[web.security]\nblock_private_ips = false\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="SSRF protections"):
        load_config(path)


def test_web_policy_requires_one_time_approval(tmp_path):
    policy = SecurityPolicy(tmp_path)
    target, reason = policy.validate_tool_call("WebSearch", {"query": "test query"})
    assert target == "test query"
    assert "Outbound" in reason
    target, reason = policy.validate_tool_call(
        "WebFetch", {"url": "https://example.org/article"}
    )
    assert target == "https://example.org/article"
    assert "approval" in reason


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/file",
        "http://127.0.0.1/admin",
        "http://localhost/admin",
        "http://metadata.google.internal/",
        "http://user:password@example.com/",
        "https://192.0.2.1/",
    ],
)
def test_web_url_policy_rejects_unsafe_targets(url):
    with pytest.raises(WebSecurityError):
        normalize_url(url)


def test_web_url_policy_normalizes_public_http_url():
    clean, host, port = normalize_url("HTTPS://Example.COM/path?q=1#fragment")
    assert clean == "https://example.com/path?q=1"
    assert host == "example.com"
    assert port == 443


def test_dns_policy_rejects_private_resolution(monkeypatch):
    async def fake_getaddrinfo(*args, **kwargs):
        return [(2, 1, 6, "", ("10.0.0.10", 443))]

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(WebSecurityError, match="non-public"):
            await resolve_public("example.org", 443)

    asyncio.run(run())


def test_citation_store_allocates_unique_ids_per_session(tmp_path):
    store = CitationStore(tmp_path / "state.sqlite3")
    store.initialize()
    page = SimpleNamespace(
        canonical_url="https://example.org/a",
        title="Example",
        fetched_at="2026-11-27T00:00:00+00:00",
        content_hash="abc123",
    )
    assert store.record("session-a", page) == "W1"
    assert store.record("session-a", page) == "W2"
    assert store.record("session-b", page) == "W1"
    assert [x["source_id"] for x in store.list_sources("session-a")] == ["W1", "W2"]
    assert store.list_sources("session-b")[0]["source_id"] == "W1"

def test_gateway_search_cache_avoids_repeated_upstream_calls():
    from harness.web.gateway import WebGateway
    from harness.web.models import SearchResult

    class FakeSearch:
        calls = 0

        async def search(self, query, limit, language, safe_search):
            self.calls += 1
            return [SearchResult("Example", "https://example.org", "snippet")]

    async def run():
        gateway = WebGateway(search_cache_ttl=60)
        fake = FakeSearch()
        gateway.search_client = fake
        first = await gateway.search("same query")
        second = await gateway.search("same query")
        assert first == second
        assert fake.calls == 1

    asyncio.run(run())


def test_web_fetch_tool_records_citation_metadata(tmp_path):
    from harness.web.tools import build_web_tool_classes
    from harness.web.citations import CitationStore

    class FakeGateway:
        async def fetch(self, url):
            return {
                "url": url, "canonical_url": url, "title": "Example page",
                "text": "Extracted text", "content_type": "text/html",
                "fetched_at": "2026-11-27T00:00:00+00:00",
                "content_hash": "hash-1",
            }

    store = CitationStore(tmp_path / "state.sqlite3")
    store.initialize()
    _, fetch_class = build_web_tool_classes(FakeGateway(), store, "session-1")
    tool = fetch_class({})
    params = tool.parameters(url="https://example.org/page")
    result = asyncio.run(tool.execute(params))
    assert result["is_error"] is False
    assert '"source_id": "W1"' in result["content"][0]["text"]
    assert store.list_sources("session-1")[0]["source_id"] == "W1"

@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@example.org/path",
        "http://127.0.0.1/admin",
        "http://metadata.google.internal/",
    ],
)
def test_web_fetch_security_policy_rejects_credentials_and_local_hosts(tmp_path, url):
    policy = SecurityPolicy(tmp_path)
    with pytest.raises(SecurityViolation):
        policy.validate_tool_call("WebFetch", {"url": url})
