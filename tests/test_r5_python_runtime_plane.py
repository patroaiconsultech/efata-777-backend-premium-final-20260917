from __future__ import annotations

import pytest
from sqlalchemy import delete, select

from conftest import Testing, headers
from orkio_v2.models import AuditEvent
from orkio_v2.services.capability_policy import CapabilityPolicy
from orkio_v2.services.python_runtime.contracts import (
    PythonRuntimeContext,
    PythonRuntimeUnavailable,
)
from orkio_v2.services.python_runtime.gateway import execute_python_runtime
from orkio_v2.services.python_tool import PythonToolDisabled, execute_python


def policy(**overrides):
    base = dict(
        python_enabled=True,
        python_timeout_seconds=2.0,
        python_max_code_bytes=20_000,
        python_max_output_bytes=64_000,
        external_read_enabled=False,
        external_read_allowed_domains=(),
        external_read_timeout_seconds=2.0,
        external_read_max_bytes=100_000,
        external_read_max_urls_per_turn=2,
        python_runtime_mode="legacy_local_test",
        python_runtime_adapter="unconfigured",
        python_legacy_local_test_enabled=True,
        python_runtime_environment="test",
        python_runtime_profile_id="python-analysis-lite-v1",
    )
    base.update(overrides)
    return CapabilityPolicy(**base)


def _clear_python_audit():
    with Testing() as db:
        db.execute(
            delete(AuditEvent).where(AuditEvent.resource_type == "python_execution")
        )
        db.commit()


@pytest.mark.asyncio
async def test_r5_minimum_patch_blocks_legacy_executor_outside_dev_test():
    p = policy(python_runtime_environment="staging")
    with pytest.raises(PythonToolDisabled, match="PYTHON_LEGACY_RUNTIME_FORBIDDEN"):
        await execute_python("print(42)", p)


def test_r5_manifest_does_not_claim_sandbox_for_legacy_local():
    manifest = policy().manifest(privileged=True)["python"]
    assert manifest["execute"] is True
    assert manifest["availableNow"] is True
    assert manifest["runtime"] == "legacy_same_host_subprocess"
    assert manifest["runtimeProved"] is False
    assert manifest["premiumQualified"] is False
    assert manifest["network_policy"] == "NOT_OS_ENFORCED"
    assert manifest["network_enforced"] is False
    assert manifest["filesystem_isolated"] is False


def test_r5_external_unconfigured_manifest_is_fail_closed():
    manifest = policy(
        python_runtime_mode="external",
        python_legacy_local_test_enabled=False,
    ).manifest(privileged=True)["python"]
    assert manifest["enabled"] is True
    assert manifest["execute"] is False
    assert manifest["availableNow"] is False
    assert manifest["runtime"] == "external_isolated_sandbox"
    assert manifest["network_policy"] == "DENY_REQUIRED"
    assert manifest["runtimeProved"] is False


@pytest.mark.asyncio
async def test_r5_external_runtime_unconfigured_has_no_local_fallback():
    p = policy(
        python_runtime_mode="external",
        python_legacy_local_test_enabled=False,
    )
    with pytest.raises(PythonRuntimeUnavailable, match="PYTHON_RUNTIME_UNAVAILABLE"):
        await execute_python_runtime(
            code="print(42)",
            policy=p,
            context=PythonRuntimeContext(
                tenant_id="tenant-1",
                user_id="user-1",
            ),
        )


def test_r5_direct_route_legacy_local_is_explicit_and_audited(client, monkeypatch):
    _clear_python_audit()
    monkeypatch.setenv("PLATFORM_PYTHON_TOOL_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_MODE", "legacy_local_test")
    monkeypatch.setenv("PLATFORM_PYTHON_LEGACY_LOCAL_TEST_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_ADAPTER", "unconfigured")

    response = client.post(
        "/api/v2/tools/python/execute",
        json={"code": "print(6*7)"},
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["stdout"].strip() == "42"
    assert payload["status"] == "SUCCEEDED"
    assert payload["runtime"] == "legacy_local_test"
    assert payload["execution_performed"] is True
    assert payload["proposal_only"] is False
    assert payload["network_policy_enforced"] is False
    assert payload["filesystem_isolation_enforced"] is False
    assert payload["cpu_limit_enforced"] is False
    assert payload["memory_limit_enforced"] is False
    assert payload["attestation"]["production_eligible"] is False

    with Testing() as db:
        events = db.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.resource_type == "python_execution",
                AuditEvent.resource_id == payload["execution_id"],
            )
            .order_by(AuditEvent.created_at, AuditEvent.id)
        ).all()
    actions = [event.action for event in events]
    assert "PYTHON_RUNTIME_STARTED" in actions
    assert "PYTHON_RUNTIME_SUCCEEDED" in actions
    serialized = repr([event.metadata_json for event in events])
    assert "print(6*7)" not in serialized
    assert payload["code_sha256"] in serialized


def test_r5_external_unconfigured_route_returns_503_and_audits_unavailable(
    client, monkeypatch
):
    _clear_python_audit()
    monkeypatch.setenv("PLATFORM_PYTHON_TOOL_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_MODE", "external")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_ADAPTER", "unconfigured")
    monkeypatch.setenv("PLATFORM_PYTHON_LEGACY_LOCAL_TEST_ENABLED", "false")

    response = client.post(
        "/api/v2/tools/python/execute",
        json={"code": "print(99)"},
        headers=headers(),
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "PYTHON_RUNTIME_UNAVAILABLE"

    with Testing() as db:
        event = db.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.resource_type == "python_execution",
                AuditEvent.action == "PYTHON_RUNTIME_UNAVAILABLE",
            )
            .order_by(AuditEvent.created_at.desc())
        )
    assert event is not None
    assert event.tenant_id == "tenant-1"
    assert event.actor_id == "user-1"
    assert event.metadata_json["code_sha256"]
    assert event.metadata_json["error_code"] == "PYTHON_RUNTIME_UNAVAILABLE"


def test_r5_member_manifest_never_exposes_execution():
    manifest = policy().manifest(privileged=False)["python"]
    assert manifest["enabled"] is False
    assert manifest["execute"] is False
    assert manifest["availableNow"] is False
