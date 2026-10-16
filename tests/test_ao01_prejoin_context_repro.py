"""AO-01 candidate-only reproduction; NOT included in deployment delta."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import ThreadParticipant, Message, Attachment, Artifact, Membership
from orkio_v2.routes import _history
from orkio_v2.services.team_runtime import team_history
from orkio_v2.services.thread_access_policy import visible_messages

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
T1 = datetime(2026, 2, 1, tzinfo=timezone.utc)


def test_from_join_direct_history_excludes_prejoin_context(client, monkeypatch, tmp_path: Path):
    cfg = get_settings()
    monkeypatch.setattr(cfg, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(cfg, "document_context_enabled", True, raising=False)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    marker = "PREJOIN-DOCUMENT-SECRET-NOT-AUTHORIZED"
    raw = marker.encode()
    key = f"tenant-1/{thread_id}/prejoin.txt"
    dest = tmp_path / key
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(raw)
    with Testing() as db:
        db.add(ThreadParticipant(
            tenant_id="tenant-1", thread_id=thread_id, user_id="user-2",
            history_access="from_join", joined_at=T1, thread_role="participant",
            active=True, allowed_agent_ids=["orkio"],
            can_view_attachments=True, can_download_artifacts=True,
        ))
        db.add(Message(
            tenant_id="tenant-1", thread_id=thread_id,
            author_type="user", author_id="user-1", content="PREJOIN-MESSAGE-HIDDEN",
            created_at=T0,
        ))
        db.add(Attachment(
            tenant_id="tenant-1", thread_id=thread_id, uploaded_by="user-1",
            filename="prejoin.txt", mime_type="text/plain", size_bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(), storage_key=key, created_at=T0,
        ))
        db.add(Artifact(
            tenant_id="tenant-1", thread_id=thread_id, created_by="user-1",
            filename="PREJOIN-ARTIFACT-SECRET.pdf", mime_type="application/pdf",
            storage_key=f"tenant-1/{thread_id}/artifacts/prejoin.pdf",
            sha256="a"*64, created_at=T0,
        ))
        db.commit()
        guest=db.query(ThreadParticipant).filter_by(thread_id=thread_id,user_id="user-2").one()
        assert visible_messages(db,thread_id=thread_id,tenant_id="tenant-1",participant=guest)==[]
        history=_history(db,thread_id,"tenant-1",cfg,participant=guest)
        context="\\n".join(m["content"] for m in history)
        assert "PREJOIN-MESSAGE-HIDDEN" not in context
        assert marker not in context
        assert "PREJOIN-ARTIFACT-SECRET" not in context


def test_from_join_team_history_excludes_prejoin_documents(client, monkeypatch, tmp_path: Path):
    cfg=get_settings()
    monkeypatch.setattr(cfg, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(cfg, "document_context_enabled", True, raising=False)
    thread_id=client.post("/api/v2/threads",json={},headers=headers()).json()["id"]
    marker="TEAM-PREJOIN-SECRET-NOT-AUTHORIZED"
    raw=marker.encode()
    key=f"tenant-1/{thread_id}/early.txt"
    dest=tmp_path/key
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_bytes(raw)
    with Testing() as db:
        guest=ThreadParticipant(tenant_id="tenant-1",thread_id=thread_id,
            user_id="user-2",history_access="from_join", joined_at=T1, active=True,
            allowed_agent_ids=["orkio"], can_view_attachments=True)
        db.add(guest)
        db.add(Attachment(tenant_id="tenant-1",thread_id=thread_id,
            uploaded_by="user-1",filename="early.txt",mime_type="text/plain",
            size_bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),storage_key=key,
            created_at=T0))
        db.commit()
        history=team_history(db,thread_id=thread_id,tenant_id="tenant-1",
            settings=cfg,participant=guest)
        assert marker not in "\\n".join(m["content"] for m in history)


def test_from_join_routes_cannot_list_or_download_earlier_artifacts_or_documents(client, monkeypatch, tmp_path: Path):
    cfg = get_settings()
    monkeypatch.setattr(cfg, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(cfg, "document_context_enabled", True, raising=False)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    art_data = b"private prejoin artifact bytes"
    art_key = f"tenant-1/{thread_id}/old-artifact.txt"
    art_target = tmp_path/art_key
    art_target.parent.mkdir(parents=True, exist_ok=True)
    art_target.write_bytes(art_data)
    doc_data = b"private prejoin document bytes"
    doc_key = f"tenant-1/{thread_id}/old-doc.txt"
    doc_target = tmp_path/doc_key
    doc_target.write_bytes(doc_data)
    with Testing() as db:
        member = ThreadParticipant(
            tenant_id="tenant-1", thread_id=thread_id, user_id="user-2",
            history_access="from_join", joined_at=T1, thread_role="participant",
            active=True, can_view_attachments=True, can_download_artifacts=True,
        )
        row = Artifact(
            tenant_id="tenant-1", thread_id=thread_id, created_by="user-1",
            filename="EARLY_ARTIFACT_PRIVATE.txt", mime_type="text/plain",
            storage_key=art_key, sha256=hashlib.sha256(art_data).hexdigest(), created_at=T0,
        )
        db.add(member)
        db.add(Membership(tenant_id="tenant-1", user_id="user-2", role="member"))
        db.add(row)
        db.add(Attachment(
            tenant_id="tenant-1", thread_id=thread_id, uploaded_by="user-1",
            filename="EARLY_DOCUMENT_PRIVATE.txt", mime_type="text/plain",
            size_bytes=len(doc_data), sha256=hashlib.sha256(doc_data).hexdigest(),
            storage_key=doc_key, created_at=T0,
        ))
        db.commit()
        artifact_id = row.id
    guest_headers = headers(user="user-2", roles="admin")
    listing = client.get(f"/api/v2/threads/{thread_id}/artifacts", headers=guest_headers)
    assert listing.status_code == 200, listing.text
    assert listing.json() == []
    download = client.get(f"/api/v2/artifacts/{artifact_id}/download", headers=guest_headers)
    assert download.status_code == 404, download.text
    provenance = client.get(f"/api/v2/threads/{thread_id}/document-context", headers=guest_headers)
    assert provenance.status_code == 200, provenance.text
    assert provenance.json()["sources"] == 0
    # Restore global SQLite fixture state; subsequent tests expect guest-only identity.
    with Testing() as db:
        db.query(Membership).filter_by(tenant_id="tenant-1", user_id="user-2").delete()
        db.commit()


def test_full_thread_history_can_include_earlier_document_with_grant(client, monkeypatch, tmp_path: Path):
    cfg = get_settings()
    monkeypatch.setattr(cfg, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(cfg, "document_context_enabled", True, raising=False)
    thread_id=client.post("/api/v2/threads",json={},headers=headers()).json()["id"]
    marker="FULL-THREAD-PREVIOUS-DOCUMENT-ALLOWED"
    raw=marker.encode()
    key=f"tenant-1/{thread_id}/old-full.txt"
    dest=tmp_path/key
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_bytes(raw)
    with Testing() as db:
        guest=ThreadParticipant(
            tenant_id="tenant-1",thread_id=thread_id,user_id="user-2",
            history_access="full_thread",joined_at=T1,active=True,
            can_view_attachments=True,
        )
        db.add(guest)
        db.add(Attachment(
            tenant_id="tenant-1", thread_id=thread_id,
            uploaded_by="user-1", filename="old-full.txt",
            mime_type="text/plain",size_bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
            storage_key=key,created_at=T0,
        ))
        db.commit()
        history=team_history(
            db,thread_id=thread_id,tenant_id="tenant-1",settings=cfg,participant=guest
        )
        assert marker in "\\n".join(m["content"] for m in history)


def test_attachment_context_requires_view_grant_even_for_postjoin_documents(client, monkeypatch, tmp_path: Path):
    cfg = get_settings()
    monkeypatch.setattr(cfg, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(cfg, "document_context_enabled", True, raising=False)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    marker = "POSTJOIN-DOC-NO-ATTACHMENT-VIEW"
    raw = marker.encode()
    key = f"tenant-1/{thread_id}/postjoin.txt"
    path = tmp_path/key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    from datetime import timedelta
    after = T1 + timedelta(seconds=1)
    with Testing() as db:
        guest = ThreadParticipant(
            tenant_id="tenant-1", thread_id=thread_id, user_id="user-2",
            history_access="from_join", joined_at=T1, active=True,
            can_view_attachments=False, can_download_artifacts=False,
        )
        db.add(guest)
        db.add(Attachment(
            tenant_id="tenant-1", thread_id=thread_id, uploaded_by="user-1",
            filename="postjoin.txt", mime_type="text/plain", size_bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(), storage_key=key, created_at=after,
        ))
        db.commit()
        direct = _history(db, thread_id, "tenant-1", cfg, participant=guest)
        team = team_history(db, thread_id=thread_id, tenant_id="tenant-1",
            settings=cfg, participant=guest)
        assert marker not in "\\n".join(m["content"] for m in direct)
        assert marker not in "\\n".join(m["content"] for m in team)
