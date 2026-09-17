from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from conftest import headers
from orkio_v2.config import get_settings
from orkio_v2.models import Attachment
from orkio_v2.services.attachment_service import (
    AttachmentIdentityConflict,
    persist_attachment,
)


def _create_thread(client) -> str:
    response = client.post(
        "/api/v2/threads",
        headers=headers(),
        json={"title": "Attachment idempotency"},
    )
    assert response.status_code == 200
    return response.json()["id"]


def test_same_file_same_thread_reuses_canonical_attachment(client, tmp_path, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "artifacts_enabled", True, raising=False)
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path), raising=False)

    thread_id = _create_thread(client)
    payload = b"EFATA-IDEMPOTENCY-777"

    first = client.post(
        f"/api/v2/threads/{thread_id}/attachments",
        headers=headers(),
        files={"file": ("facts.txt", payload, "text/plain")},
    )
    second = client.post(
        f"/api/v2/threads/{thread_id}/attachments",
        headers=headers(),
        files={"file": ("facts.txt", payload, "text/plain")},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["reused"] is False
    assert second.json()["reused"] is True


def test_same_content_different_thread_does_not_cross_scope(client, tmp_path, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "artifacts_enabled", True, raising=False)
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path), raising=False)

    thread_a = _create_thread(client)
    thread_b = _create_thread(client)
    payload = b"SAME-CONTENT-DIFFERENT-THREAD"

    a = client.post(
        f"/api/v2/threads/{thread_a}/attachments",
        headers=headers(),
        files={"file": ("facts.txt", payload, "text/plain")},
    )
    b = client.post(
        f"/api/v2/threads/{thread_b}/attachments",
        headers=headers(),
        files={"file": ("facts.txt", payload, "text/plain")},
    )

    assert a.status_code == 200
    assert b.status_code == 200
    assert a.json()["id"] != b.json()["id"]
    assert a.json()["reused"] is False
    assert b.json()["reused"] is False


class _Diag:
    constraint_name = "attachments_storage_key_key"


class _UniqueViolation(Exception):
    sqlstate = "23505"
    diag = _Diag()


class _RaceSession:
    def __init__(self, canonical: Attachment):
        self.canonical = canonical
        self.scalar_calls = 0
        self.rollback_called = False

    def scalar(self, _statement):
        self.scalar_calls += 1
        if self.scalar_calls == 1:
            return None
        return self.canonical

    def add(self, _row):
        return None

    def commit(self):
        raise IntegrityError(
            "INSERT INTO attachments ...",
            {},
            _UniqueViolation("duplicate"),
        )

    def rollback(self):
        self.rollback_called = True


def test_concurrent_unique_conflict_recovers_canonical_row(tmp_path):
    data = b"RACE-SAFE"
    canonical = Attachment(
        id="att-canonical",
        tenant_id="tenant-1",
        thread_id="thread-1",
        uploaded_by="user-1",
        filename="facts.txt",
        mime_type="text/plain",
        size_bytes=len(data),
        sha256="abc123",
        storage_key="tenant-1/thread-1/abc123-facts.txt",
    )
    db = _RaceSession(canonical)
    target = tmp_path / canonical.storage_key

    result = persist_attachment(
        db,
        tenant_id="tenant-1",
        thread_id="thread-1",
        uploaded_by="user-1",
        filename="facts.txt",
        mime_type="text/plain",
        data=data,
        sha256="abc123",
        storage_key=canonical.storage_key,
        target=target,
    )

    assert db.rollback_called is True
    assert result.created is False
    assert result.reused is True
    assert result.attachment.id == "att-canonical"


def test_existing_storage_identity_mismatch_fails_closed(tmp_path):
    data = b"EXPECTED"
    existing = Attachment(
        id="att-existing",
        tenant_id="tenant-1",
        thread_id="thread-1",
        uploaded_by="user-1",
        filename="facts.txt",
        mime_type="text/plain",
        size_bytes=4,
        sha256="different",
        storage_key="tenant-1/thread-1/key",
    )

    class _ExistingSession:
        def scalar(self, _statement):
            return existing

    with pytest.raises(AttachmentIdentityConflict):
        persist_attachment(
            _ExistingSession(),
            tenant_id="tenant-1",
            thread_id="thread-1",
            uploaded_by="user-1",
            filename="facts.txt",
            mime_type="text/plain",
            data=data,
            sha256="expected",
            storage_key=existing.storage_key,
            target=tmp_path / existing.storage_key,
        )
