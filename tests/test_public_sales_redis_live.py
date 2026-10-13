"""Redis-real B1.1 rehearsal. SKIP is NOT proof of runtime qualification.

Run ONLY with an isolated test Redis:
PUBLIC_SALES_TEST_REDIS_URL=redis://... PUBLIC_SALES_TEST_CONFIRM_ISOLATED_REDIS=YES
PYTHONPATH=src pytest -q tests/test_public_sales_redis_live.py -rs
No production/staging URL should be supplied here.
"""
import asyncio
import hashlib
import os
import secrets
import subprocess
import sys

import pytest

from orkio_v2 import public_sales_redis as store

ISOLATED = (
    bool(os.getenv("PUBLIC_SALES_TEST_REDIS_URL"))
    and os.getenv("PUBLIC_SALES_TEST_CONFIRM_ISOLATED_REDIS") == "YES"
)
pytestmark = pytest.mark.skipif(not ISOLATED, reason="ISOLATED_REDIS_NOT_CONFIGURED: no runtime proof")

@pytest.fixture(autouse=True)
def real_redis(monkeypatch):
    if not ISOLATED:
        yield
        return
    monkeypatch.setenv("PUBLIC_SALES_STORAGE_BACKEND", "redis")
    monkeypatch.setenv("PUBLIC_SALES_DISTRIBUTED_APPROVED", "true")
    monkeypatch.setenv("PUBLIC_SALES_REDIS_URL", os.environ["PUBLIC_SALES_TEST_REDIS_URL"])
    monkeypatch.setenv("PUBLIC_SALES_RATE_KEY_SECRET", "public-sales-test-secret-not-used-in-production-32")
    monkeypatch.setattr(store, "_PREFIX", f"efata:public-sales:b11:isolated:{secrets.token_hex(12)}")
    yield

def run(coro):
    return asyncio.run(coro)

def test_a01_invalid_attempts_consume_per_session_limit():
    async def scenario():
        token, _ = await store.create_shared_session(
            intent="understand_platform", client_ip="203.0.113.31"
        )
        assert token not in {"rate_limited", "capacity"}
        catalog = {"understand_platform": {"explore": ["choice_1", "choice_2"]}}
        responses = [
            await store.transition_shared_session(
                token=token, action_id="invalid", intent_hint=None,
                client_ip="203.0.113.31", catalog=catalog,
            )
            for _ in range(16)
        ]
        assert all(x[0] == "invalid" for x in responses[:15]), responses
        assert responses[15][0] == "rate_limited"
    run(scenario())

def test_a02_global_capacity_is_atomic_under_concurrency():
    async def scenario():
        # Isolated namespace; limit to three concurrent live sessions.
        prefix = store._PREFIX
        requests = []
        for _ in range(20):
            digest = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
            requests.append(store._eval(store._CREATE, [
                f"{prefix}:session:{digest}", f"{prefix}:capacity",
                f"{prefix}:create:isolatedip",
            ], ["understand_platform", 5000, 10000, 25, 60000, 3, digest]))
        replies = await asyncio.gather(*requests)
        statuses = [reply[0] for reply in replies]
        assert statuses.count(1) == 3, statuses
        assert statuses.count(-2) == 17, statuses
    run(scenario())

def test_a02_expiration_replay_and_transition_between_independent_processes():
    async def scenario():
        token, _ = await store.create_shared_session(
            intent="understand_platform", client_ip="203.0.113.32"
        )
        assert token not in {"rate_limited", "capacity"}
        return token
    token = run(scenario())
    # Run the first transition in a different Python process with independent
    # module state and the very same Redis test namespace.
    source = """
import asyncio,os
from orkio_v2 import public_sales_redis as s
s._PREFIX=os.environ["B11_TEST_PREFIX"]
async def main():
    outcome,*_=await s.transition_shared_session(
        token=os.environ["B11_TEST_TOKEN"],action_id="explore",
        intent_hint=None,client_ip="203.0.113.32",
        catalog={"understand_platform":{"explore":["choice_1","choice_2"]}})
    assert outcome=="followup", outcome
asyncio.run(main())
"""
    env = os.environ.copy()
    env.update({
        "PUBLIC_SALES_STORAGE_BACKEND": "redis",
        "PUBLIC_SALES_DISTRIBUTED_APPROVED": "true",
        "PUBLIC_SALES_REDIS_URL": os.environ["PUBLIC_SALES_TEST_REDIS_URL"],
        "PUBLIC_SALES_RATE_KEY_SECRET": "public-sales-test-secret-not-used-in-production-32",
        "B11_TEST_PREFIX": store._PREFIX, "B11_TEST_TOKEN": token,
    })
    result = subprocess.run([sys.executable, "-c", source], env=env,
        timeout=20, capture_output=True, text=True)
    assert result.returncode == 0, "cross-process shared transition did not pass"
    async def complete():
        return await store.transition_shared_session(
            token=token, action_id="choice_1", intent_hint=None,
            client_ip="203.0.113.32",
            catalog={"understand_platform":{"explore":["choice_1","choice_2"]}},
        )
    assert run(complete())[0] == "result"
    assert run(complete())[0] == "completed"

def test_a02_expiry_from_redis_clock():
    async def scenario():
        digest = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        prefix = store._PREFIX
        created = await store._eval(store._CREATE, [
            f"{prefix}:session:{digest}", f"{prefix}:capacity",
            f"{prefix}:create:expiry-ip",
        ], ["understand_platform", 35, 200, 8, 60000, 1000, digest])
        assert created[0] == 1
        await asyncio.sleep(0.07)
        result = await store._eval(store._TRANSITION, [
            f"{prefix}:session:{digest}",
            f"{prefix}:message-session:{digest}",
            f"{prefix}:message-client:expiry-ip",
        ], ['{"understand_platform":{"explore":["choice_1","choice_2"]}}',
            "explore", "", 60000, 15, 60, secrets.token_hex(16), 1800000])
        assert result[0] == -2, result
    run(scenario())
