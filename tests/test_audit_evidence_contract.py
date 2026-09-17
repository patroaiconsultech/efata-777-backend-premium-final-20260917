from __future__ import annotations

import pytest
from pydantic import ValidationError

import orkio_v2.schemas as schemas
from orkio_v2.schemas import (
    AuditArchiveInspectRequest,
    AuditFileInspectRequest,
    AuditRuntimeFileSha256Request,
    AuditRuntimeSearchMarkerRequest,
)
from orkio_v2.services.audit_evidence import AuditEvidenceError, build_evidence_envelope


def _envelope(**overrides):
    base = dict(
        request_id="req-1",
        execution_id="exec-1",
        tenant_id="patroai",
        user_id="u1",
        capability_id="audit.file.inspect@1.0.0",
        capability_version="1.0.0",
        environment="test",
        deployment_id="local-candidate-002",
        requested_agent_id="nata",
        resolved_agent_id="nata",
        turn_owner_agent_id="nata",
        capability_decision="ALLOW",
        capability_decision_reason="ALLOW",
        status="completed",
        sanitized=True,
        read_executed=True,
        root_id="evidence",
        data={"relative_path": "docs/a.txt"},
    )
    base.update(overrides)
    return build_evidence_envelope(**base)


def test_canonical_evidence_envelope_contains_frozen_identity_governance_and_timing_fields():
    payload = _envelope().to_dict()
    required = {
        "audit_execution_id",
        "request_id",
        "execution_id",
        "tenant_id",
        "user_id",
        "capability_id",
        "capability_version",
        "environment",
        "deployment_id",
        "requested_agent_id",
        "resolved_agent_id",
        "turn_owner_agent_id",
        "capability_decision",
        "capability_decision_reason",
        "status",
        "sanitized",
        "read_executed",
        "write_executed",
        "migration_executed",
        "deploy_executed",
        "human_approval_required",
        "started_at",
        "finished_at",
        "created_at",
    }
    assert required.issubset(payload)
    assert payload["capability_version"] == "1.0.0"
    assert payload["environment"] == "test"
    assert payload["write_executed"] is False
    assert payload["migration_executed"] is False
    assert payload["deploy_executed"] is False
    assert payload["human_approval_required"] is True
    assert payload["sanitized"] is True
    assert len(payload["audit_execution_id"]) >= 32


def test_evidence_output_is_bounded_and_readonly_invariant_is_fail_closed():
    envelope = _envelope(data={"content": "x" * 1000})
    with pytest.raises(AuditEvidenceError, match="OUTPUT_TOO_LARGE"):
        envelope.to_dict(max_serialized_bytes=256)

    with pytest.raises(AuditEvidenceError, match="READONLY_INVARIANT"):
        _envelope(write_executed=True)

    with pytest.raises(AuditEvidenceError, match="DENIED_READ_EXECUTED"):
        _envelope(
            capability_decision="DENY",
            capability_decision_reason="AUDIT_CAPABILITY_DISABLED",
            status="denied",
            read_executed=True,
        )


def test_file_schema_freezes_operation_max_bytes_and_utf8_marker_contract():
    req = AuditFileInspectRequest(
        root_id="evidence",
        relative_path="docs/a.txt",
        operation="read_text",
        max_bytes=4096,
    )
    assert req.operation == "read_text"
    assert req.max_bytes == 4096

    marker_512_bytes = "é" * 256
    req = AuditFileInspectRequest(
        root_id="evidence",
        relative_path="docs/a.txt",
        operation="search_marker",
        marker=marker_512_bytes,
    )
    assert len(req.marker.encode("utf-8")) == 512

    with pytest.raises(ValidationError):
        AuditFileInspectRequest(
            root_id="evidence",
            relative_path="docs/a.txt",
            operation="search_marker",
            marker="é" * 257,
        )
    for bad in ("a\x00b", "a\nb", "a\tb", "a\x85b"):
        with pytest.raises(ValidationError):
            AuditFileInspectRequest(
                root_id="evidence",
                relative_path="docs/a.txt",
                operation="search_marker",
                marker=bad,
            )


def test_archive_schema_rejects_client_physical_path_and_freezes_operations():
    with pytest.raises(ValidationError):
        AuditArchiveInspectRequest.model_validate(
            {"path": "/tmp/a.zip", "agent_id": "nata", "operation": "manifest"}
        )

    manifest = AuditArchiveInspectRequest(
        artifact_id="artifact-1", operation="manifest", manifest_limit=100
    )
    assert manifest.member is None

    metadata = AuditArchiveInspectRequest(
        root_id="evidence",
        relative_path="a.zip",
        operation="file_metadata",
        member="docs/a.txt",
    )
    assert metadata.member == "docs/a.txt"

    for operation in ("read_text_member", "hash_member"):
        req = AuditArchiveInspectRequest(
            root_id="evidence",
            relative_path="a.zip",
            operation=operation,
            member="docs/a.txt",
            max_bytes=4096,
        )
        assert req.operation == operation

    with pytest.raises(ValidationError):
        AuditArchiveInspectRequest(
            root_id="evidence",
            relative_path="a.zip",
            operation="hash_member",
        )


def test_runtime_requests_are_separate_and_legacy_combined_schema_is_absent():
    hashed = AuditRuntimeFileSha256Request(module_id="core")
    searched = AuditRuntimeSearchMarkerRequest(
        module_id="core", marker="return", max_matches=256
    )
    assert hashed.module_id == "core"
    assert searched.marker == "return"
    assert not hasattr(schemas, "AuditRuntimeInspectRequest")
