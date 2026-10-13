"""Redis candidate contract tests: no Redis service is available in this harness.

These tests verify wiring and fail-closed behavior, not cross-replica correctness.
A real Redis concurrency/load test remains mandatory before public activation.
"""
import asyncio

from fastapi.testclient import TestClient
import pytest

from orkio_v2.config import get_settings
from orkio_v2.main import app
from orkio_v2 import public_sales_redis as store

PREFIX = "/api/v2/public/sales-sessions"
HEADERS = {"Origin": "http://localhost:5173", "Content-Type": "application/json"}

@pytest.fixture(autouse=True)
def flags(monkeypatch):
    monkeypatch.setenv("PUBLIC_SALES_ENABLED", "true")
    monkeypatch.setenv("PUBLIC_SALES_LLM_ENABLED", "false")
    monkeypatch.setenv("PUBLIC_SALES_STORAGE_BACKEND", "redis")
    monkeypatch.setenv("PUBLIC_SALES_RATE_KEY_SECRET", "K" * 48)
    monkeypatch.setattr(get_settings(), "environment", "production")
    yield

def test_gate_defaults_to_closed(monkeypatch):
    monkeypatch.delenv("PUBLIC_SALES_DISTRIBUTED_APPROVED", raising=False)
    assert not store.shared_store_gate_ready()
    assert TestClient(app).post(PREFIX, json={}, headers=HEADERS).status_code == 503
    monkeypatch.setenv("PUBLIC_SALES_DISTRIBUTED_APPROVED", "true")
    monkeypatch.delenv("PUBLIC_SALES_REDIS_URL", raising=False)
    assert not store.shared_store_gate_ready()
    assert TestClient(app).post(PREFIX, json={}, headers=HEADERS).status_code == 503

def test_broken_redis_connection_fails_closed_without_private_state(monkeypatch):
    monkeypatch.setenv("PUBLIC_SALES_DISTRIBUTED_APPROVED", "true")
    monkeypatch.setenv("PUBLIC_SALES_REDIS_URL", "redis://127.0.0.1:1")
    result = TestClient(app).post(PREFIX, json={"entry_intent":"understand_platform"},headers=HEADERS)
    assert result.status_code == 503
    assert result.json()["detail"] == "PUBLIC_SALES_SHARED_STORE_UNAVAILABLE"
    assert "password" not in result.text.lower()

def test_production_delegates_creation_and_transition_to_shared_store(monkeypatch):
    monkeypatch.setenv("PUBLIC_SALES_DISTRIBUTED_APPROVED", "true")
    monkeypatch.setenv("PUBLIC_SALES_REDIS_URL", "redis://example.invalid:6379")
    calls = []
    async def eval_mock(script, keys, args):
        calls.append((script, keys, args))
        if "capacity" in keys[1]:
            return [1, 1799999999999]
        return [1, b"understand_platform", b"explore", 1799999999999]
    monkeypatch.setattr(store, "_eval", eval_mock)
    client = TestClient(app)
    created = client.post(PREFIX, json={"entry_intent":"understand_platform"}, headers=HEADERS)
    assert created.status_code == 201
    token = created.json()["session_id"]
    assert len(token) >= 40
    assert token not in str(calls)
    assert created.json()["opening"]["experience"]["mode"] == "editorial"
    advanced = client.post(f"{PREFIX}/{token}/messages", json={"action_id":"explore"}, headers=HEADERS)
    assert advanced.status_code == 200
    assert advanced.json()["experience"]["step"] == 2
    assert len(calls) == 2
    assert all("efata:public-sales:b11:v1" in k for call in calls for k in call[1])
    assert "127.0.0.1" not in str(calls)

def test_malformed_redis_reply_is_never_success(monkeypatch):
    monkeypatch.setenv("PUBLIC_SALES_DISTRIBUTED_APPROVED", "true")
    monkeypatch.setenv("PUBLIC_SALES_REDIS_URL", "redis://example.invalid")
    async def bad_eval(*_args):
        return ["OK"]
    monkeypatch.setattr(store, "_eval", bad_eval)
    response = TestClient(app).post(PREFIX, json={}, headers=HEADERS)
    assert response.status_code == 503

def test_action_error_outcomes_have_explicit_mapping(monkeypatch):
    monkeypatch.setenv("PUBLIC_SALES_DISTRIBUTED_APPROVED", "true")
    monkeypatch.setenv("PUBLIC_SALES_REDIS_URL", "redis://example.invalid")
    async def mock_eval(script, keys, args):
        if "message-session:" in keys[1]:
            return [-5, b"understand_platform", b"", 0]
        return [1, 1799999999999]
    monkeypatch.setattr(store, "_eval", mock_eval)
    client = TestClient(app)
    token = client.post(PREFIX,json={},headers=HEADERS).json()["session_id"]
    rejected = client.post(f"{PREFIX}/{token}/messages",json={"action_id":"god_mode"},headers=HEADERS)
    assert rejected.status_code == 409
    assert rejected.json()["detail"] == "PUBLIC_SALES_ACTION_INVALID"

def test_a01_session_limit_precedes_invalid_and_duplicate_action_handling():
    """Source-level ordering invariant; real Redis behavior is separately gated."""
    script = store._TRANSITION
    assert script.index("ZREMRANGEBYSCORE',KEYS[2]") < script.index("local step=tonumber(item.step)")
    assert script.index("ZADD',KEYS[2]") < script.index("local branches=catalog[item.intent]")
    assert script.index("ZCARD',KEYS[2]") < script.index("if step >= 2")
    assert "PEXPIRE',KEYS[2],window)" in script
