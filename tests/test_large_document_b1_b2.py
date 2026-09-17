from __future__ import annotations

from pathlib import Path
import io

import pytest
from fastapi import UploadFile
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from orkio_v2.auth import Principal
from orkio_v2.config import Settings, get_settings
from orkio_v2.database import Base
from orkio_v2.models import (
    KnowledgeDocumentChunk,
    KnowledgeDocumentDerivative,
    KnowledgeDocumentSection,
    Membership,
    Tenant,
    User,
)
from orkio_v2.services.blob_storage import LocalBlobStorage
from orkio_v2.services.knowledge_repository import create_uploaded_document
from orkio_v2.services.knowledge_retrieval import build_knowledge_context
from conftest import headers

from orkio_v2.services.large_document import (
    LargeDocumentError,
    canonical_context_for_document,
    process_document,
    save_selection,
    stage_upload,
    structure_payload,
)


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        session.add(Tenant(id="tenant-a", name="Tenant A"))
        session.add(User(
            id="user-a",
            external_subject="sub-user-a",
            email="user-a@example.com",
            display_name="User A",
        ))
        session.add(Membership(tenant_id="tenant-a", user_id="user-a", role="member"))
        session.commit()
        yield session


def principal() -> Principal:
    return Principal(
        user_id="user-a",
        tenant_id="tenant-a",
        roles=("member",),
        external_subject="sub-user-a",
        email="user-a@example.com",
    )


def settings(tmp_path: Path, *, selective: bool = True) -> Settings:
    return Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        PLATFORM_ARTIFACT_STORAGE_PATH=str(tmp_path),
        PLATFORM_KNOWLEDGE_PLANE_ENABLED=True,
        PLATFORM_LARGE_DOCUMENT_PIPELINE_ENABLED=True,
        PLATFORM_KNOWLEDGE_SELECTIVE_CONTEXT_ENABLED=selective,
        PLATFORM_KNOWLEDGE_MAX_UPLOAD_BYTES=524_288_000,
        PLATFORM_KNOWLEDGE_AUTO_PROCESS_BYTES=32_000_000,
        PLATFORM_KNOWLEDGE_CHUNK_TARGET_CHARS=1200,
        PLATFORM_KNOWLEDGE_CHUNK_OVERLAP_CHARS=100,
        PLATFORM_KNOWLEDGE_RETRIEVAL_TOP_K=4,
    )


def create_source(db, tmp_path: Path):
    body = (
        "# Manual de Operações\n"
        "Introdução geral.\n\n"
        "## Alfa\n"
        + ("banana processo alfa estabilidade operação " * 120)
        + "\n\n## Beta\n"
        + ("contrato beta financeiro governança compliance " * 120)
    ).encode()
    return create_uploaded_document(
        db,
        principal=principal(),
        scope="PERSONAL",
        title="Manual",
        filename="manual.md",
        mime_type="text/markdown",
        data=body,
        digest=None,
        classification="internal",
        allowed_purposes=["chat"],
        agent_id=None,
        expires_at=None,
        storage=LocalBlobStorage(tmp_path),
    )


@pytest.mark.asyncio
async def test_stage_upload_streams_and_enforces_limit(tmp_path):
    cfg = settings(tmp_path)
    payload = b"x" * (2 * 1024 * 1024 + 17)
    upload = UploadFile(filename="large.txt", file=io.BytesIO(payload))
    staged = await stage_upload(
        upload,
        settings=cfg,
        max_bytes=len(payload),
        chunk_bytes=64 * 1024,
    )
    assert staged.size_bytes == len(payload)
    assert staged.path.stat().st_size == len(payload)
    assert staged.sha256
    staged.path.unlink(missing_ok=True)

    too_large = UploadFile(filename="large.txt", file=io.BytesIO(payload))
    with pytest.raises(LargeDocumentError) as raised:
        await stage_upload(
            too_large,
            settings=cfg,
            max_bytes=len(payload) - 1,
            chunk_bytes=64 * 1024,
        )
    assert raised.value.code == "FILE_TOO_LARGE"


def test_local_blob_storage_file_and_range_api(tmp_path):
    storage = LocalBlobStorage(tmp_path / "blob")
    source = tmp_path / "source.bin"
    source.write_bytes(b"0123456789" * 1000)
    assert storage.put_file_if_absent("a/b.bin", source, content_type="application/octet-stream")
    assert storage.read_range("a/b.bin", 10, 20) == b"0123456789"
    materialized = tmp_path / "copy.bin"
    storage.materialize("a/b.bin", materialized)
    assert materialized.read_bytes() == source.read_bytes()


def test_process_creates_canonical_sections_and_chunks(db, tmp_path):
    row = create_source(db, tmp_path)
    derivative = process_document(
        db,
        document=row,
        storage=LocalBlobStorage(tmp_path),
        settings=settings(tmp_path),
    )
    assert derivative.status == "READY"
    assert derivative.storage_key
    assert derivative.canonical_chars and derivative.canonical_chars > 0
    sections = list(db.scalars(
        select(KnowledgeDocumentSection)
        .where(KnowledgeDocumentSection.knowledge_id == row.id)
        .order_by(KnowledgeDocumentSection.ordinal)
    ).all())
    chunks = list(db.scalars(
        select(KnowledgeDocumentChunk)
        .where(KnowledgeDocumentChunk.knowledge_id == row.id)
        .order_by(KnowledgeDocumentChunk.ordinal)
    ).all())
    assert any(section.heading == "Alfa" for section in sections)
    assert any(section.heading == "Beta" for section in sections)
    assert len(chunks) >= 4

    payload = structure_payload(db, document=row)
    assert payload["derivative"]["status"] == "READY"
    assert payload["chunk_count"] == len(chunks)


def test_auto_retrieval_uses_relevant_chunks_without_source_blob_get(db, tmp_path):
    row = create_source(db, tmp_path)
    cfg = settings(tmp_path)
    base_storage = LocalBlobStorage(tmp_path)
    process_document(db, document=row, storage=base_storage, settings=cfg)

    class RangeOnlyStorage:
        def read_range(self, key, start, end):
            return base_storage.read_range(key, start, end)
        def get(self, _key):
            raise AssertionError("full blob get should not be used by canonical retrieval")

    result = canonical_context_for_document(
        db,
        storage=RangeOnlyStorage(),
        document=row,
        tenant_id="tenant-a",
        user_id="user-a",
        query="banana estabilidade",
        max_chars=5000,
        top_k=2,
    )
    assert result is not None
    text, provided, truncated = result
    assert "banana" in text
    assert "financeiro governança" not in text
    assert provided <= 5000


def test_manual_section_selection_overrides_query_ranking(db, tmp_path):
    row = create_source(db, tmp_path)
    cfg = settings(tmp_path)
    storage = LocalBlobStorage(tmp_path)
    process_document(db, document=row, storage=storage, settings=cfg)

    beta = db.scalar(
        select(KnowledgeDocumentSection).where(
            KnowledgeDocumentSection.knowledge_id == row.id,
            KnowledgeDocumentSection.heading == "Beta",
        )
    )
    assert beta is not None
    save_selection(
        db,
        document=row,
        principal=principal(),
        mode="MANUAL",
        section_ids=[beta.id],
    )

    result = canonical_context_for_document(
        db,
        storage=storage,
        document=row,
        tenant_id="tenant-a",
        user_id="user-a",
        query="banana estabilidade",  # query points to Alfa, manual selection wins
        max_chars=5000,
        top_k=2,
    )
    assert result is not None
    text, _, _ = result
    assert "financeiro governança" in text
    assert "banana processo alfa" not in text


def test_build_knowledge_context_uses_selective_canonical_path(db, tmp_path):
    row = create_source(db, tmp_path)
    cfg = settings(tmp_path)
    storage = LocalBlobStorage(tmp_path)
    process_document(db, document=row, storage=storage, settings=cfg)

    bundle = build_knowledge_context(
        db,
        settings=cfg,
        tenant_id="tenant-a",
        user_id="user-a",
        purpose="chat",
        execution_id="exec-selective",
        thread_id="thread-a",
        agent_id="orkio",
        query_text="banana estabilidade",
    )
    assert bundle is not None
    content = "\n".join(item["content"] for item in bundle.messages)
    assert "banana" in content
    assert bundle.provided_chars <= cfg.knowledge_context_max_chars_per_file


def test_http_pipeline_process_structure_selection(client, tmp_path, monkeypatch):
    cfg = get_settings()
    monkeypatch.setattr(cfg, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(cfg, "knowledge_plane_enabled", True, raising=False)
    monkeypatch.setattr(cfg, "large_document_pipeline_enabled", True, raising=False)
    monkeypatch.setattr(cfg, "knowledge_selective_context_enabled", True, raising=False)
    monkeypatch.setattr(cfg, "knowledge_large_document_max_upload_bytes", 524_288_000, raising=False)
    monkeypatch.setattr(cfg, "knowledge_large_document_auto_process_bytes", 32_000_000, raising=False)
    monkeypatch.setattr(cfg, "knowledge_large_document_max_pdf_pages", 5000, raising=False)
    monkeypatch.setattr(cfg, "knowledge_chunk_target_chars", 1200, raising=False)
    monkeypatch.setattr(cfg, "knowledge_chunk_overlap_chars", 100, raising=False)
    monkeypatch.setattr(cfg, "knowledge_retrieval_top_k", 4, raising=False)

    content = (
        "# Documento HTTP\n"
        "## Segurança\n"
        + ("tenant isolamento auditoria " * 100)
        + "\n## Comercial\n"
        + ("receita clientes vendas " * 100)
    ).encode()
    upload = client.post(
        "/api/v2/knowledge",
        headers=headers(),
        data={"scope": "PERSONAL", "title": "Documento HTTP"},
        files={"file": ("http.md", content, "text/markdown")},
    )
    assert upload.status_code == 200, upload.text
    body = upload.json()
    assert body["processing"]["status"] == "READY"
    document_id = body["id"]

    structure = client.get(
        f"/api/v2/knowledge/{document_id}/structure",
        headers=headers(),
    )
    assert structure.status_code == 200, structure.text
    payload = structure.json()
    assert payload["chunk_count"] > 0
    security = next(item for item in payload["sections"] if item["heading"] == "Segurança")

    selection = client.put(
        f"/api/v2/knowledge/{document_id}/selection",
        headers=headers(),
        json={"mode": "MANUAL", "section_ids": [security["id"]]},
    )
    assert selection.status_code == 200, selection.text
    assert selection.json()["mode"] == "MANUAL"

    preview = client.get(
        f"/api/v2/knowledge/{document_id}/content",
        headers=headers(),
        params=[("section_ids", security["id"]), ("max_chars", "5000")],
    )
    assert preview.status_code == 200, preview.text
    combined = "\n".join(item["content"] for item in preview.json()["sections"])
    assert "tenant isolamento" in combined
    assert "receita clientes" not in combined
