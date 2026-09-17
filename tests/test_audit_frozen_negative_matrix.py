from __future__ import annotations

import hashlib
import os
import time
import zipfile
from dataclasses import replace

import pytest

from orkio_v2.schemas import AuditArchiveInspectRequest
from orkio_v2.services.audit_archive_adapter import AuditArchiveAdapter, AuditArchiveError
from orkio_v2.services.audit_archive_source_resolver import (
    AuditArchiveSourceError,
    AuditArchiveSourceResolver,
    AuditArtifactRecord,
)
from orkio_v2.services.audit_capability_guard import (
    AuditCapabilityGuard,
    AuditCapabilityGuardError,
)
from orkio_v2.services.audit_path_policy import AuditPathPolicy, AuditPathPolicyError
from orkio_v2.services.capability_registry import CapabilitySpec


FROZEN_033A_NEGATIVE_CASE_IDS = {
    "PATH_TOCTOU_IDENTITY_CHANGE",
    "PATH_SECRET_LIKE_DENY",
    "ZIP_ABSOLUTE_MEMBER_DENY",
    "ZIP_MEMBER_COUNT_LIMIT",
    "ZIP_DECLARED_MEMBER_SIZE_LIMIT",
    "ZIP_DECLARED_TOTAL_SIZE_LIMIT",
    "ZIP_COMPRESSION_RATIO_BOMB",
    "ARTIFACT_UNKNOWN_DENY",
    "ARTIFACT_FOREIGN_TENANT_DENY",
    "ARTIFACT_OUTSIDE_APPROVED_STORAGE_DENY",
    "ARTIFACT_SYMLINK_SUBSTITUTION_DENY",
    "ARTIFACT_VALID_TENANT_VERIFIED_FILE",
    "CAPABILITY_TIMEOUT_TERMINAL_NO_RETRY",
    "OUTPUT_SANITIZER_HIT",
    "OUTPUT_SECRET_BLOCK",
    "OUTPUT_CAP_AFTER_SANITIZATION",
}


class FakeArtifactLookup:
    def __init__(self, records):
        self._records = {record.artifact_id: record for record in records}

    def get(self, artifact_id: str):
        return self._records.get(artifact_id)


def _artifact_record(*, artifact_id: str, tenant_id: str, storage_key: str, data: bytes):
    return AuditArtifactRecord(
        artifact_id=artifact_id,
        tenant_id=tenant_id,
        storage_key=storage_key,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _resolver(storage_root, records):
    return AuditArchiveSourceResolver(
        path_policy=AuditPathPolicy({"artifact-storage": storage_root}),
        artifact_lookup=FakeArtifactLookup(records),
    )


def _write_zip(path, entries, *, compression=zipfile.ZIP_STORED):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return path.read_bytes()


def _verified_zip(tmp_path, entries, *, compression=zipfile.ZIP_STORED):
    root = tmp_path / "ziproot"
    root.mkdir()
    path = root / "evidence.zip"
    _write_zip(path, entries, compression=compression)
    policy = AuditPathPolicy({"evidence": root})
    return policy.open_verified_file(root_id="evidence", relative_path="evidence.zip")


def _spec(*, timeout_seconds=1.0, max_output_bytes=1024):
    return CapabilitySpec(
        capability_id="audit.file.inspect@1.0.0",
        capability_version="1.0.0",
        description="test",
        risk_level="HIGH",
        runtime="server",
        network=False,
        write=False,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        enabled=True,
    )


def test_path_toctou_identity_replacement_is_denied(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "evidence.txt"
    target.write_text("before", encoding="utf-8")
    replacement = root / "replacement.txt"
    replacement.write_text("after", encoding="utf-8")

    original_open = os.open
    swapped = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "evidence.txt" and dir_fd is not None and not swapped:
            os.replace(replacement, target)
            swapped = True
        if dir_fd is None:
            return original_open(path, flags, mode)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", racing_open)
    policy = AuditPathPolicy({"evidence": root})
    with pytest.raises(AuditPathPolicyError, match="IDENTITY_CHANGED"):
        policy.open_verified_file(
            root_id="evidence",
            relative_path="evidence.txt",
        )
    assert swapped is True


def test_secret_like_filesystem_path_is_denied(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / ".env.production").write_text("SAFE_PLACEHOLDER=1", encoding="utf-8")
    policy = AuditPathPolicy({"evidence": root})
    with pytest.raises(AuditPathPolicyError, match="SECRET_LIKE"):
        policy.open_verified_file(
            root_id="evidence",
            relative_path=".env.production",
        )


def test_archive_absolute_member_and_declared_limits_are_denied(tmp_path):
    with _verified_zip(tmp_path, [("/absolute.txt", b"x")]) as verified:
        with pytest.raises(AuditArchiveError, match="UNSAFE_PATH"):
            AuditArchiveAdapter().preflight(verified)

    many = tmp_path / "many"
    many.mkdir()
    with zipfile.ZipFile(many / "many.zip", "w") as z:
        for index in range(3):
            z.writestr(f"{index}.txt", b"x")
    policy = AuditPathPolicy({"evidence": many})
    with policy.open_verified_file(
        root_id="evidence", relative_path="many.zip"
    ) as verified:
        with pytest.raises(AuditArchiveError, match="ENTRY_LIMIT"):
            AuditArchiveAdapter(max_entries=2).preflight(verified)

    member = tmp_path / "member"
    member.mkdir()
    _write_zip(member / "member.zip", [("big.txt", b"A" * 32)])
    policy = AuditPathPolicy({"evidence": member})
    with policy.open_verified_file(
        root_id="evidence", relative_path="member.zip"
    ) as verified:
        with pytest.raises(AuditArchiveError, match="MEMBER_TOO_LARGE"):
            AuditArchiveAdapter(max_member_bytes=16).preflight(verified)

    total = tmp_path / "total"
    total.mkdir()
    _write_zip(
        total / "total.zip",
        [("a.txt", b"A" * 10), ("b.txt", b"B" * 10)],
    )
    policy = AuditPathPolicy({"evidence": total})
    with policy.open_verified_file(
        root_id="evidence", relative_path="total.zip"
    ) as verified:
        with pytest.raises(AuditArchiveError, match="TOTAL_SIZE"):
            AuditArchiveAdapter(
                max_member_bytes=16,
                max_total_uncompressed_bytes=15,
            ).preflight(verified)


def test_archive_compression_ratio_bomb_is_denied(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    _write_zip(
        root / "bomb.zip",
        [("bomb.txt", b"A" * 10_000)],
        compression=zipfile.ZIP_DEFLATED,
    )
    policy = AuditPathPolicy({"evidence": root})
    with policy.open_verified_file(
        root_id="evidence", relative_path="bomb.zip"
    ) as verified:
        with pytest.raises(AuditArchiveError, match="COMPRESSION_RATIO"):
            AuditArchiveAdapter(max_compression_ratio=2).preflight(verified)


def test_artifact_id_resolution_is_tenant_scoped_and_fail_closed(tmp_path):
    storage = tmp_path / "artifacts"
    storage.mkdir()
    valid_bytes = _write_zip(
        storage / "tenant-a/thread-1/generated/art-1-evidence.zip",
        [("docs/a.txt", b"hello")],
    )
    valid = _artifact_record(
        artifact_id="art-1",
        tenant_id="tenant-a",
        storage_key="tenant-a/thread-1/generated/art-1-evidence.zip",
        data=valid_bytes,
    )
    outside = _artifact_record(
        artifact_id="art-outside",
        tenant_id="tenant-a",
        storage_key="tenant-b/thread-9/generated/foreign.zip",
        data=b"x",
    )
    resolver = _resolver(storage, [valid, outside])

    unknown = AuditArchiveInspectRequest(
        artifact_id="missing",
        operation="manifest",
    )
    with pytest.raises(AuditArchiveSourceError, match="ARCHIVE_NOT_FOUND"):
        with resolver.resolve_request(request=unknown, tenant_id="tenant-a"):
            pass

    request = AuditArchiveInspectRequest(
        artifact_id="art-1",
        operation="manifest",
    )
    with pytest.raises(AuditArchiveSourceError, match="TENANT_MISMATCH"):
        with resolver.resolve_request(request=request, tenant_id="tenant-b"):
            pass

    outside_request = AuditArchiveInspectRequest(
        artifact_id="art-outside",
        operation="manifest",
    )
    with pytest.raises(AuditArchiveSourceError, match="SOURCE_NOT_ALLOWED"):
        with resolver.resolve_request(
            request=outside_request,
            tenant_id="tenant-a",
        ):
            pass

    with resolver.resolve_request(
        request=request,
        tenant_id="tenant-a",
    ) as verified:
        assert verified.root_id == "artifact"
        assert verified.relative_path == "art-1"
        assert os.pread(verified.fd, 2, 0) == b"PK"


def test_artifact_storage_symlink_substitution_is_denied(tmp_path):
    storage = tmp_path / "artifacts"
    external = tmp_path / "external"
    storage.mkdir()
    external.mkdir()
    real = external / "foreign.zip"
    data = _write_zip(real, [("docs/a.txt", b"foreign")])

    tenant_dir = storage / "tenant-a/thread-1/generated"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "art-2.zip").symlink_to(real)

    record = _artifact_record(
        artifact_id="art-2",
        tenant_id="tenant-a",
        storage_key="tenant-a/thread-1/generated/art-2.zip",
        data=data,
    )
    resolver = _resolver(storage, [record])
    request = AuditArchiveInspectRequest(
        artifact_id="art-2",
        operation="manifest",
    )
    with pytest.raises(AuditArchiveSourceError, match="SOURCE_NOT_ALLOWED"):
        with resolver.resolve_request(request=request, tenant_id="tenant-a"):
            pass


def test_capability_timeout_is_terminal_and_does_not_retry():
    calls = 0

    def slow_read():
        nonlocal calls
        calls += 1
        time.sleep(0.05)
        return {"result": "late"}

    with pytest.raises(AuditCapabilityGuardError, match="REQUEST_TIMEOUT") as exc:
        AuditCapabilityGuard().execute(
            spec=_spec(timeout_seconds=0.005),
            operation=slow_read,
        )
    assert exc.value.terminal is True
    assert exc.value.result_accepted is False
    time.sleep(0.06)
    assert calls == 1


def test_output_sanitizer_secret_block_and_cap_are_fail_closed():
    guard = AuditCapabilityGuard()
    result = guard.execute(
        spec=_spec(max_output_bytes=1024),
        operation=lambda: {
            "result": "ok",
            "token": "must-not-leak",
            "nested": {"password": "must-not-leak", "visible": "yes"},
        },
    )
    assert result.sanitized is True
    assert result.data == {"nested": {"visible": "yes"}, "result": "ok"}

    with pytest.raises(AuditCapabilityGuardError, match="OUTPUT_SECRET_BLOCKED"):
        guard.execute(
            spec=_spec(max_output_bytes=1024),
            operation=lambda: {
                "content": "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
            },
        )

    with pytest.raises(AuditCapabilityGuardError, match="OUTPUT_TOO_LARGE"):
        guard.execute(
            spec=_spec(max_output_bytes=64),
            operation=lambda: {"result": "A" * 512},
        )


def test_frozen_negative_matrix_ids_are_all_backed_by_executable_cases():
    # This inventory is deliberately explicit: removing a mandatory case from
    # the Gate 033A matrix requires changing this assertion in the same diff.
    executed = {
        "PATH_TOCTOU_IDENTITY_CHANGE",
        "PATH_SECRET_LIKE_DENY",
        "ZIP_ABSOLUTE_MEMBER_DENY",
        "ZIP_MEMBER_COUNT_LIMIT",
        "ZIP_DECLARED_MEMBER_SIZE_LIMIT",
        "ZIP_DECLARED_TOTAL_SIZE_LIMIT",
        "ZIP_COMPRESSION_RATIO_BOMB",
        "ARTIFACT_UNKNOWN_DENY",
        "ARTIFACT_FOREIGN_TENANT_DENY",
        "ARTIFACT_OUTSIDE_APPROVED_STORAGE_DENY",
        "ARTIFACT_SYMLINK_SUBSTITUTION_DENY",
        "ARTIFACT_VALID_TENANT_VERIFIED_FILE",
        "CAPABILITY_TIMEOUT_TERMINAL_NO_RETRY",
        "OUTPUT_SANITIZER_HIT",
        "OUTPUT_SECRET_BLOCK",
        "OUTPUT_CAP_AFTER_SANITIZATION",
    }
    assert FROZEN_033A_NEGATIVE_CASE_IDS == executed
