"""WEB-01: tenant-scoped rollout to all provisioned users and enabled agents.

All test traffic is local: no Brave or Redis egress is permitted.
"""
import json

import pytest

from orkio_v2.agents.registry import list_agents
from orkio_v2.services import web_search as web


TENANT_GRANT = {
    "permission": "web.search.execute",
    "tenant_id": "tenant-1",
    "user_scope": "provisioned_users",
    "agent_scope": "enabled_catalog",
}


@pytest.fixture
def policy(monkeypatch):
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_AUTONOMOUS_ENABLED", "false")
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_ALLOWED_ENVIRONMENTS", "test")
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_GRANTS_JSON", json.dumps([TENANT_GRANT]))


def _check(*, tenant="tenant-1", user="user-1", agent="orkio", environment="test"):
    return web._authorized(tenant=tenant, user=user, agent=agent, environment=environment)


def _denied(**kwargs):
    with pytest.raises(web.WebSearchError, match="WEB_SEARCH_PERMISSION_DENIED") as e:
        _check(**kwargs)
    assert e.value.denied


def test_all_33_enabled_catalog_agents_can_be_scoped_to_one_tenant(policy):
    agents = list_agents()
    assert len(agents) == 33
    for agent in agents:
        _check(user="user-1", agent=agent.slug)
        _check(user="user-2", agent=agent.slug)


@pytest.mark.parametrize("invalid_tenant", ["tenant-2", "", "*"])
def test_other_tenant_denied(policy, invalid_tenant):
    _denied(tenant=invalid_tenant)


@pytest.mark.parametrize("agent", ["*", "not_registered", "ORkIO", "", " id:orkio"])
def test_only_canonical_enabled_agent_ids_are_allowed(policy, agent):
    _denied(agent=agent)


@pytest.mark.parametrize("invalid", [
    {"permission":"web.search.execute","tenant_id":"*",
     "user_scope":"provisioned_users","agent_scope":"enabled_catalog"},
    {"permission":"web.search.execute","tenant_id":"tenant-1",
     "user_scope":"*","agent_scope":"enabled_catalog"},
    {"permission":"web.search.execute","tenant_id":"tenant-1",
     "user_scope":"provisioned_users","agent_scope":"*"},
    {"permission":"web.search.autonomous","tenant_id":"tenant-1",
     "user_scope":"provisioned_users","agent_scope":"enabled_catalog"},
    {"permission":"web.search.execute","tenant_id":"tenant-1",
     "user_scope":"provisioned_users","agent_scope":"enabled_catalog",
     "user_id":"user-1"},
    {"permission":"web.search.execute","tenant_id":"tenant-1",
     "user_scope":"provisioned_users","agent_scope":"enabled_catalog",
     "agent_id":"orkio"},
])
def test_ambiguous_broad_or_cross_tenant_grants_fail_closed(policy, monkeypatch, invalid):
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_GRANTS_JSON", json.dumps([invalid]))
    _denied()


def test_exact_legacy_grants_remain_supported(policy, monkeypatch):
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_GRANTS_JSON", json.dumps([{
        "permission": "web.search.execute", "tenant_id": "tenant-1",
        "user_id": "user-1", "agent_id": "orkio",
    }]))
    _check()
    _denied(user="user-2")
    _denied(agent="orion")


@pytest.mark.parametrize("broken", ["", "{}", "null", "true", "[1]", "{invalid"])
def test_invalid_grant_configuration_fails_closed(policy, monkeypatch, broken):
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_GRANTS_JSON", broken)
    _denied()


def test_global_flag_autonomous_flag_and_environment_gate_remain_closed(policy, monkeypatch):
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_ENABLED", "false")
    with pytest.raises(web.WebSearchError, match="WEB_SEARCH_DISABLED"):
        _check()
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_AUTONOMOUS_ENABLED", "true")
    with pytest.raises(web.WebSearchError, match="WEB_SEARCH_AUTONOMOUS_DISABLED"):
        _check()
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_AUTONOMOUS_ENABLED", "false")
    _denied(environment="production")


def test_unlisted_tenant_cannot_inherit_another_tenants_grant(policy, monkeypatch):
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_GRANTS_JSON", json.dumps([
        TENANT_GRANT, {
            "permission": "web.search.execute",
            "tenant_id": "tenant-2", "user_id": "user-x", "agent_id": "orkio"
        }
    ]))
    _check(tenant="tenant-1",user="another")
    _denied(tenant="tenant-2", user="another")
    _check(tenant="tenant-2",user="user-x")


# Direct HTTP-route tests verify canonical membership and thread ACL.
from contextlib import contextmanager

from conftest import Testing, headers
from orkio_v2 import routes
from orkio_v2.services import llm
from orkio_v2.config import get_settings
from orkio_v2.models import Membership, ThreadParticipant
from sqlalchemy import select


@contextmanager
def _membership_state(*, active: bool):
    """Isolate membership changes in the session-global SQLite fixture."""
    with Testing() as db:
        membership = db.scalar(select(Membership).where(
            Membership.tenant_id == "tenant-1", Membership.user_id == "user-2"))
        missing = membership is None
        original = (membership.active, membership.role) if membership else None
        if membership is None:
            membership = Membership(
                tenant_id="tenant-1", user_id="user-2",
                role="member", active=active)
            db.add(membership)
        else:
            membership.active = active
            membership.role = "member"
        db.commit()
    try:
        yield
    finally:
        with Testing() as db:
            membership = db.scalar(select(Membership).where(
                Membership.tenant_id == "tenant-1", Membership.user_id == "user-2"))
            if missing:
                if membership is not None:
                    db.delete(membership)
            elif membership is not None:
                membership.active, membership.role = original
            db.commit()


def _forbid_egress(monkeypatch):
    invoked = []
    async def unexpected(**kwargs):
        invoked.append(kwargs)
        raise AssertionError("WEB-01 must not execute before canonical auth and ACL")
    monkeypatch.setattr(routes, "execute_explicit_web_search", unexpected)
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-fake", raising=False)
    return invoked


def test_unprovisioned_user_is_denied_before_provider(client, policy, monkeypatch):
    invoked = _forbid_egress(monkeypatch)
    with _membership_state(active=False):
        thread = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
        response = client.post(
            f"/api/v2/threads/{thread}/messages",
            json={"content": "Pesquise na internet notícias de hoje"},
            headers=headers(user="user-2", tenant="tenant-1", subject="sub-2"))
        assert response.status_code == 403
        assert not invoked


def test_provisioned_user_cannot_search_foreign_thread(client, policy, monkeypatch):
    invoked = _forbid_egress(monkeypatch)
    with _membership_state(active=True):
        thread = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
        response = client.post(
            f"/api/v2/threads/{thread}/messages",
            json={"content": "Pesquise na internet notícias de hoje"},
            headers=headers(user="user-2", tenant="tenant-1", subject="sub-2"))
        assert response.status_code in (403, 404), response.text
        assert not invoked


def test_active_tenant_user_searches_only_own_thread(client, policy, monkeypatch):
    """Real JSON route: canonical auth and ACL, then service grant and one mocked egress."""
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-fake", raising=False)
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", "test-fake-not-a-real-secret")
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_REDIS_URL", "redis://localhost:6379")
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_REDIS_KEY_SECRET", "a" * 48)
    monkeypatch.setenv("PLATFORM_WEB_SEARCH_UNIT_COST_USD_MICROS", "5000")
    invoked = []
    async def reserve(*args, **kwargs):
        invoked.append(("reserve", kwargs))
        return ["slot"] * 8, "member"
    async def release(*args, **kwargs):
        invoked.append(("release", None))
    async def provider(query, token):
        invoked.append(("provider", query))
        return web.normalize_brave({"grounding": {"generic": [{
            "title": "Known source",
            "url": "https://example.org/report",
            "snippets": ["A current report"],
        }]}}, "2026-10-14T10:00:00Z")
    async def generate(*args, **kwargs):
        return "Resultado com fonte [S1]."
    monkeypatch.setattr(web.RedisWebBudget, "reserve", reserve)
    monkeypatch.setattr(web.RedisWebBudget, "release", release)
    monkeypatch.setattr(web, "_provider_query", provider)
    monkeypatch.setattr(llm, "generate", generate)

    with _membership_state(active=True):
        head = headers(user="user-2", tenant="tenant-1", subject="sub-2")
        thread_resp = client.post("/api/v2/threads", json={}, headers=head)
        assert thread_resp.status_code == 200, thread_resp.text
        thread = thread_resp.json()["id"]
        result = client.post(
            f"/api/v2/threads/{thread}/messages",
            json={"content": "Pesquise na internet notícias de hoje"},
            headers=head)
        assert result.status_code == 200, result.text
        assert result.json()["web_search"]["status"] == "completed"
        assert "https://example.org/report" in result.json()["content"]
        assert [entry[0] for entry in invoked] == ["reserve", "provider", "release"]
        assert invoked[0][1]["tenant"] == "tenant-1"
        assert invoked[0][1]["user"] == "user-2"


def test_viewer_cannot_search_even_with_tenant_wide_grant(client, policy, monkeypatch):
    invoked = _forbid_egress(monkeypatch)
    with _membership_state(active=True):
        h = headers(user="user-2", tenant="tenant-1", subject="sub-2")
        thread = client.post("/api/v2/threads", json={}, headers=h).json()["id"]
        with Testing() as db:
            participant = db.scalar(select(ThreadParticipant).where(
                ThreadParticipant.thread_id == thread,
                ThreadParticipant.tenant_id == "tenant-1",
                ThreadParticipant.user_id == "user-2"))
            participant.thread_role = "viewer"
            db.commit()
        resp = client.post(
            f"/api/v2/threads/{thread}/messages",
            json={"content": "Pesquise na internet notícias de hoje"},
            headers=h)
        assert resp.status_code == 403, resp.text
        assert not invoked


def test_tenant_grant_cannot_enable_research_without_requested_search(client, policy, monkeypatch):
    monkeypatch.setattr(get_settings(), "openai_api_key", "test-fake", raising=False)
    async def unexpected(**kwargs):
        raise AssertionError("WEB-01 must be explicitly requested")
    async def generate(*args, **kwargs):
        return "Resposta normal"
    monkeypatch.setattr(routes, "execute_explicit_web_search", unexpected)
    monkeypatch.setattr(llm, "generate", generate)
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    response = client.post(
        f"/api/v2/threads/{thread}/messages",
        json={"content": "Explique como funciona um sistema de busca."},
        headers=headers())
    assert response.status_code == 200, response.text
    assert "web_search" not in response.json()
