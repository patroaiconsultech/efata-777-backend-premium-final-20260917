from __future__ import annotations

from pathlib import Path
import hashlib

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import Attachment
from orkio_v2.services.document_context import build_document_context


def _attach_text(db, *, root: Path, thread_id: str, attachment_id: str, text: str):
    raw = text.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    key = f"tenant-1/{thread_id}/{digest}-{attachment_id}.txt"
    target = root / key
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    db.add(
        Attachment(
            id=attachment_id,
            tenant_id="tenant-1",
            thread_id=thread_id,
            uploaded_by="user-1",
            filename=f"{attachment_id}.txt",
            mime_type="text/plain",
            size_bytes=len(raw),
            sha256=digest,
            storage_key=key,
            status="ready",
        )
    )
    db.commit()


def test_document_provenance_distinguishes_source_provided_and_per_file_truncation(
    client, monkeypatch, tmp_path
):
    settings = get_settings()
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(settings, "document_context_max_chars_per_file", 20_000, raising=False)
    monkeypatch.setattr(settings, "document_context_max_chars", 48_000, raising=False)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    sentinel_a = "ORKIO-SENTINEL-A"
    sentinel_b = "ORKIO-SENTINEL-B"
    text = sentinel_a + ("x" * (20_050 - len(sentinel_a))) + sentinel_b
    with Testing() as db:
        _attach_text(db, root=tmp_path, thread_id=thread_id, attachment_id="doc-a", text=text)
        bundle = build_document_context(
            db, settings=settings, tenant_id="tenant-1", thread_id=thread_id
        )
    assert bundle is not None
    p = bundle.provenance
    assert p.available is True
    assert p.source_chars > 20_000
    assert p.provided_chars <= 20_000
    assert p.per_source_truncated is True
    assert p.aggregate_truncated is False
    assert p.truncated is True
    assert sentinel_a in bundle.message["content"]
    assert sentinel_b not in bundle.message["content"]
    assert "[document context truncated]" in bundle.message["content"]


def test_document_provenance_exposes_aggregate_truncation_across_sources(
    client, monkeypatch, tmp_path
):
    settings = get_settings()
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(settings, "document_context_max_chars_per_file", 20_000, raising=False)
    monkeypatch.setattr(settings, "document_context_max_chars", 25_000, raising=False)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    with Testing() as db:
        _attach_text(db, root=tmp_path, thread_id=thread_id, attachment_id="doc-c", text="C"*15_000)
        _attach_text(db, root=tmp_path, thread_id=thread_id, attachment_id="doc-d", text="D"*15_000)
        bundle = build_document_context(
            db, settings=settings, tenant_id="tenant-1", thread_id=thread_id
        )
    assert bundle is not None
    p = bundle.provenance
    assert p.source_chars == 30_000
    assert p.provided_chars <= 25_000
    assert p.per_source_truncated is False
    assert p.aggregate_truncated is True
    assert p.truncated is True
    assert p.provided_chars <= p.source_chars
