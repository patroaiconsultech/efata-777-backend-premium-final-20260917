from __future__ import annotations

from orkio_v2.services.capability_policy import CapabilityPolicy
from orkio_v2.services.capability_registry import (
    AUDIT_ARCHIVE_INSPECT,
    AUDIT_FILE_INSPECT,
    AUDIT_RUNTIME_FILE_SHA256,
    AUDIT_RUNTIME_SEARCH_MARKER,
    CAPABILITY_VERSION,
    FROZEN_AUDIT_CAPABILITY_IDS,
    CapabilityRegistry,
    TrustedCapabilityContext,
)


def policy(**overrides) -> CapabilityPolicy:
    base = dict(
        python_enabled=False,
        python_timeout_seconds=2.0,
        python_max_code_bytes=20_000,
        python_max_output_bytes=64_000,
        external_read_enabled=False,
        external_read_allowed_domains=(),
        external_read_timeout_seconds=2.0,
        external_read_max_bytes=100_000,
        external_read_max_urls_per_turn=2,
        audit_evidence_capabilities_enabled=True,
        audit_file_inspect_enabled=True,
        audit_archive_inspect_enabled=True,
        audit_runtime_inspect_enabled=True,
        audit_runtime_file_sha256_enabled=True,
        audit_runtime_search_marker_enabled=True,
        audit_allowed_agent_ids=("nata",),
        audit_allowed_tenant_ids=("patroai",),
        audit_allowed_environments=("test",),
        audit_timeout_seconds=2.0,
        audit_max_output_bytes=128_000,
    )
    base.update(overrides)
    return CapabilityPolicy(**base)


def context(**overrides) -> TrustedCapabilityContext:
    base = dict(
        user_id="u1",
        tenant_id="patroai",
        environment="test",
        requested_agent_id="nata",
        resolved_agent_id="nata",
        turn_owner_agent_id="nata",
        privileged_user=True,
    )
    base.update(overrides)
    return TrustedCapabilityContext(**base)


def test_frozen_capability_contract_is_exactly_four_versioned_surfaces():
    registry = CapabilityRegistry(policy=policy(), rate_limit_check=lambda **_: True)
    manifest = registry.manifest()
    assert tuple(item["capability_id"] for item in manifest) == FROZEN_AUDIT_CAPABILITY_IDS
    assert FROZEN_AUDIT_CAPABILITY_IDS == (
        "audit.file.inspect@1.0.0",
        "audit.archive.inspect@1.0.0",
        "audit.runtime.file_sha256@1.0.0",
        "audit.runtime.search_marker@1.0.0",
    )
    assert all(item["capability_version"] == CAPABILITY_VERSION for item in manifest)
    assert len(manifest) == 4


def test_runtime_capabilities_have_independent_policy_surfaces():
    registry = CapabilityRegistry(
        policy=policy(audit_runtime_search_marker_enabled=False),
        rate_limit_check=lambda **_: True,
    )
    by_id = {item["capability_id"]: item for item in registry.manifest()}
    assert by_id[AUDIT_RUNTIME_FILE_SHA256]["enabled"] is True
    assert by_id[AUDIT_RUNTIME_SEARCH_MARKER]["enabled"] is False
    assert registry.authorize(
        AUDIT_RUNTIME_FILE_SHA256, context=context()
    ).allowed is True
    assert registry.authorize(
        AUDIT_RUNTIME_SEARCH_MARKER, context=context()
    ).reason == "AUDIT_CAPABILITY_DISABLED"


def test_audit_capabilities_default_fail_closed(monkeypatch):
    names = [
        "PLATFORM_AUDIT_EVIDENCE_CAPABILITIES_ENABLED",
        "PLATFORM_AUDIT_FILE_INSPECT_ENABLED",
        "PLATFORM_AUDIT_ARCHIVE_INSPECT_ENABLED",
        "PLATFORM_AUDIT_RUNTIME_INSPECT_ENABLED",
        "PLATFORM_AUDIT_RUNTIME_FILE_SHA256_ENABLED",
        "PLATFORM_AUDIT_RUNTIME_SEARCH_MARKER_ENABLED",
        "PLATFORM_AUDIT_ALLOWED_AGENT_IDS",
        "PLATFORM_AUDIT_ALLOWED_TENANT_IDS",
        "PLATFORM_AUDIT_ALLOWED_ENVIRONMENTS",
    ]
    for name in names:
        monkeypatch.delenv(name, raising=False)
    p = CapabilityPolicy.from_env()
    registry = CapabilityRegistry(policy=p)
    assert all(item["enabled"] is False for item in registry.manifest())
    audit_manifest = p.manifest(privileged=True)["audit"]
    assert audit_manifest["file_inspect"] is False
    assert audit_manifest["runtime_file_sha256"] is False
    assert audit_manifest["runtime_search_marker"] is False


def test_canonical_resolved_agent_is_authorization_subject_and_mismatch_denied():
    registry = CapabilityRegistry(policy=policy(), rate_limit_check=lambda **_: True)
    decision = registry.authorize(
        AUDIT_FILE_INSPECT,
        context=context(requested_agent_id="orion", resolved_agent_id="nata"),
    )
    assert decision.allowed is False
    assert decision.authorization_subject == "nata"
    assert decision.reason == "AUDIT_CAPABILITY_AGENT_IDENTITY_MISMATCH"


def test_privileged_user_does_not_substitute_for_unauthorized_agent():
    registry = CapabilityRegistry(policy=policy(), rate_limit_check=lambda **_: True)
    decision = registry.authorize(
        AUDIT_FILE_INSPECT,
        context=context(resolved_agent_id="orion", requested_agent_id="orion"),
    )
    assert decision.allowed is False
    assert decision.reason == "AUDIT_CAPABILITY_AGENT_DENIED"


def test_authorized_agent_does_not_substitute_for_unauthorized_user():
    registry = CapabilityRegistry(policy=policy(), rate_limit_check=lambda **_: True)
    decision = registry.authorize(
        AUDIT_FILE_INSPECT,
        context=context(privileged_user=False),
    )
    assert decision.allowed is False
    assert decision.reason == "AUDIT_CAPABILITY_USER_DENIED"


def test_user_agent_tenant_environment_and_rate_limit_intersection():
    registry = CapabilityRegistry(policy=policy(), rate_limit_check=lambda **_: True)
    allowed = registry.authorize(AUDIT_FILE_INSPECT, context=context())
    assert allowed.allowed is True
    assert allowed.reason == "ALLOW"

    tenant_denied = registry.authorize(
        AUDIT_FILE_INSPECT, context=context(tenant_id="foreign")
    )
    assert tenant_denied.reason == "AUDIT_CAPABILITY_TENANT_DENIED"

    env_denied = registry.authorize(
        AUDIT_FILE_INSPECT, context=context(environment="production")
    )
    assert env_denied.reason == "AUDIT_CAPABILITY_ENVIRONMENT_DENIED"

    no_limiter = CapabilityRegistry(policy=policy()).authorize(
        AUDIT_ARCHIVE_INSPECT, context=context()
    )
    assert no_limiter.reason == "AUDIT_RATE_LIMITER_UNAVAILABLE"

    limited = CapabilityRegistry(
        policy=policy(), rate_limit_check=lambda **_: False
    ).authorize(AUDIT_FILE_INSPECT, context=context())
    assert limited.reason == "AUDIT_REQUEST_RATE_LIMITED"
