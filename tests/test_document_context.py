from __future__ import annotations

import hashlib
import io
import zipfile

import pytest
from sqlalchemy.orm import Session

from orkio_v2.config import get_settings
from orkio_v2.database import get_db
from orkio_v2.models import Attachment
from orkio_v2.services.document_context import (
    DocumentExtractionFailed,
    DocumentIntegrityError,
    document_context_message,
    extract_document_text,
)


def _docx_bytes(text: str) -> bytes:
    content_types = b"""<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="xml" ContentType="application/xml"/>
</Types>"""
    document = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>' + text + '</w:t></w:r></w:p></w:body></w:document>'
    ).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("word/document.xml", document)
    return buf.getvalue()


def test_extracts_utf8_text_and_docx():
    assert extract_document_text(
        filename="facts.txt",
        mime_type="text/plain",
        raw="MARKER-EFATA-777".encode(),
        max_chars=1000,
        max_pdf_pages=10,
    ) == "MARKER-EFATA-777"

    docx = _docx_bytes("DOCX-MARKER-777")
    assert extract_document_text(
        filename="facts.docx",
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        raw=docx,
        max_chars=1000,
        max_pdf_pages=10,
    ) == "DOCX-MARKER-777"


def test_rejects_pdf_magic_mismatch_and_empty_text():
    with pytest.raises(DocumentIntegrityError):
        extract_document_text(
            filename="fake.pdf",
            mime_type="application/pdf",
            raw=b"not a pdf",
            max_chars=1000,
            max_pdf_pages=10,
        )
    with pytest.raises(DocumentExtractionFailed):
        extract_document_text(
            filename="empty.txt",
            mime_type="text/plain",
            raw=b"",
            max_chars=1000,
            max_pdf_pages=10,
        )


def test_context_is_tenant_and_thread_scoped(client, tmp_path, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(settings, "document_context_enabled", True, raising=False)

    data = b"ONLY-THREAD-A-CAN-READ-THIS"
    digest = hashlib.sha256(data).hexdigest()
    path = tmp_path / "tenant-1/thread-a/facts.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

    dependency = client.app.dependency_overrides[get_db]
    # The test suite override yields the shared SQLite session factory indirectly.
    db_gen = dependency()
    db: Session = next(db_gen)
    try:
        db.add(Attachment(
            id="att-a",
            tenant_id="tenant-1",
            thread_id="thread-a",
            uploaded_by="user-1",
            filename="facts.txt",
            mime_type="text/plain",
            size_bytes=len(data),
            sha256=digest,
            storage_key="tenant-1/thread-a/facts.txt",
        ))
        db.commit()

        context = document_context_message(
            db,
            settings=settings,
            tenant_id="tenant-1",
            thread_id="thread-a",
        )
        assert context is not None
        assert "ONLY-THREAD-A-CAN-READ-THIS" in context["content"]

        assert document_context_message(
            db,
            settings=settings,
            tenant_id="tenant-1",
            thread_id="thread-b",
        ) is None
        assert document_context_message(
            db,
            settings=settings,
            tenant_id="tenant-2",
            thread_id="thread-a",
        ) is None
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass


def test_sha_mismatch_is_reported_not_silently_ignored(client, tmp_path, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(settings, "document_context_enabled", True, raising=False)

    path = tmp_path / "tenant-1/thread-x/facts.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"tampered")

    dependency = client.app.dependency_overrides[get_db]
    db_gen = dependency()
    db: Session = next(db_gen)
    try:
        db.add(Attachment(
            id="att-x",
            tenant_id="tenant-1",
            thread_id="thread-x",
            uploaded_by="user-1",
            filename="facts.txt",
            mime_type="text/plain",
            size_bytes=8,
            sha256="0" * 64,
            storage_key="tenant-1/thread-x/facts.txt",
        ))
        db.commit()
        context = document_context_message(
            db,
            settings=settings,
            tenant_id="tenant-1",
            thread_id="thread-x",
        )
        assert context is not None
        assert "DOCUMENT_INTEGRITY_ERROR" in context["content"] or "DOCUMENT_SHA256_MISMATCH" in context["content"]
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass
