from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import logging
from pathlib import Path
import tempfile

from sqlalchemy.orm import Session

from ..auth import Principal
from ..models import AuditEvent, Attachment
from .attachment_service import AttachmentIdentityConflict, persist_attachment
from .blob_storage import BlobStorageError, build_blob_storage
from .large_document import (
    LargeDocumentError,
    build_structure,
    canonicalize_source,
    hash_file,
)


logger = logging.getLogger("orkio.document_intake")

INTAKE_MANIFEST_SUFFIX = ".intake-v1.json"
INTAKE_MANIFEST_SCHEMA = "efata.thread_document_intake.v1"


class UnifiedDocumentIntakeError(RuntimeError):
    def __init__(self, code: str, status_code: int = 409):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class PasteIntakeResult:
    attachment: Attachment
    reused: bool
    source_sha256: str
    source_chars: int
    canonical_sha256: str
    canonical_chars: int
    sections: int
    chunks: int
    manifest_key: str


def manifest_key_for_storage(storage_key: str) -> str:
    return f"{storage_key}{INTAKE_MANIFEST_SUFFIX}"


def _safe_title(value: str | None, source_sha256: str) -> str:
    title = " ".join(str(value or "").replace("\x00", "").split()).strip()
    return (title or f"Documento colado {source_sha256[:12]}")[:240]


def _manifest_bytes(
    *,
    tenant_id: str,
    thread_id: str,
    source_sha256: str,
    source_chars: int,
    canonical_sha256: str,
    canonical_chars: int,
    canonical_size_bytes: int,
    title: str,
    sections,
    chunks,
) -> bytes:
    payload = {
        "schema": INTAKE_MANIFEST_SCHEMA,
        "source_kind": "LARGE_PASTE",
        "tenant_id": tenant_id,
        "thread_id": thread_id,
        "title": title,
        "source_sha256": source_sha256,
        "source_chars": source_chars,
        "canonical_sha256": canonical_sha256,
        "canonical_chars": canonical_chars,
        "canonical_size_bytes": canonical_size_bytes,
        "sections": [
            {
                "id": row.id,
                "ordinal": row.ordinal,
                "heading": row.heading,
                "level": row.level,
                "page_start": row.page_start,
                "page_end": row.page_end,
                "byte_start": row.byte_start,
                "byte_end": row.byte_end,
                "estimated_tokens": row.estimated_tokens,
                "parent_id": row.parent_id,
            }
            for row in sections
        ],
        "chunks": [
            {
                "id": row.id,
                "ordinal": row.ordinal,
                "section_id": row.section_id,
                "byte_start": row.byte_start,
                "byte_end": row.byte_end,
                "estimated_tokens": row.estimated_tokens,
                "text_sha256": row.text_sha256,
                "terms": list(row.terms),
            }
            for row in chunks
        ],
    }
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _validate_existing_manifest(
    raw: bytes,
    *,
    tenant_id: str,
    thread_id: str,
    source_sha256: str,
    canonical_sha256: str,
) -> None:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UnifiedDocumentIntakeError("DOCUMENT_INTAKE_MANIFEST_CONFLICT", 409) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != INTAKE_MANIFEST_SCHEMA
        or payload.get("tenant_id") != tenant_id
        or payload.get("thread_id") != thread_id
        or payload.get("source_sha256") != source_sha256
        or payload.get("canonical_sha256") != canonical_sha256
    ):
        raise UnifiedDocumentIntakeError("DOCUMENT_INTAKE_MANIFEST_CONFLICT", 409)


def ingest_large_paste(
    db: Session,
    *,
    settings,
    principal: Principal,
    thread_id: str,
    content: str,
    title: str | None,
) -> PasteIntakeResult:
    if not getattr(settings, "unified_document_intake_enabled", False):
        raise UnifiedDocumentIntakeError("DOCUMENT_INTAKE_DISABLED", 403)

    if "\x00" in content:
        raise UnifiedDocumentIntakeError("PASTE_CONTENT_INVALID", 422)

    source_chars = len(content)
    threshold = max(
        1, int(getattr(settings, "document_intake_large_paste_threshold_chars", 100_000))
    )
    max_chars = max(
        threshold + 1,
        int(getattr(settings, "document_intake_large_paste_max_chars", 5_000_000)),
    )
    if source_chars <= threshold:
        raise UnifiedDocumentIntakeError("PASTE_BELOW_DOCUMENT_THRESHOLD", 422)
    if source_chars > max_chars:
        raise UnifiedDocumentIntakeError("PASTE_TOO_LARGE", 413)

    source_bytes = content.encode("utf-8")
    max_bytes = max(
        1, int(getattr(settings, "document_intake_large_paste_max_bytes", 20_000_000))
    )
    if len(source_bytes) > max_bytes:
        raise UnifiedDocumentIntakeError("PASTE_TOO_LARGE", 413)

    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    safe_title = _safe_title(title, source_sha256)
    filename = f"paste-{source_sha256[:12]}.md"

    try:
        with tempfile.TemporaryDirectory(prefix="efata-intake-") as temporary:
            source_path = Path(temporary) / "paste.md"
            source_path.write_bytes(source_bytes)

            canonical = canonicalize_source(
                source_path,
                mime_type="text/markdown",
                filename=filename,
                settings=settings,
            )
            sections, chunks = build_structure(
                canonical.path,
                chunk_target_chars=int(settings.knowledge_chunk_target_chars),
                chunk_overlap_chars=int(settings.knowledge_chunk_overlap_chars),
            )
            canonical_sha256 = hash_file(canonical.path)
            canonical_bytes = canonical.path.read_bytes()
    except LargeDocumentError as exc:
        raise UnifiedDocumentIntakeError(exc.code, exc.status_code) from exc

    storage_key = (
        f"{principal.tenant_id}/{thread_id}/document-intake/"
        f"{canonical_sha256}-{filename}"
    )
    manifest_key = manifest_key_for_storage(storage_key)
    manifest_bytes = _manifest_bytes(
        tenant_id=principal.tenant_id,
        thread_id=thread_id,
        source_sha256=source_sha256,
        source_chars=source_chars,
        canonical_sha256=canonical_sha256,
        canonical_chars=canonical.canonical_chars,
        canonical_size_bytes=len(canonical_bytes),
        title=safe_title,
        sections=sections,
        chunks=chunks,
    )
    if len(manifest_bytes) > int(
        getattr(settings, "document_intake_manifest_max_bytes", 2_000_000)
    ):
        raise UnifiedDocumentIntakeError("DOCUMENT_INTAKE_MANIFEST_TOO_LARGE", 413)

    storage = build_blob_storage(settings)
    manifest_created = False
    try:
        manifest_created = storage.put_if_absent(
            manifest_key,
            manifest_bytes,
            content_type="application/json",
        )
        if not manifest_created:
            _validate_existing_manifest(
                storage.get(manifest_key),
                tenant_id=principal.tenant_id,
                thread_id=thread_id,
                source_sha256=source_sha256,
                canonical_sha256=canonical_sha256,
            )

        persisted = persist_attachment(
            db,
            tenant_id=principal.tenant_id,
            thread_id=thread_id,
            uploaded_by=principal.user_id,
            filename=filename,
            mime_type="text/markdown",
            data=canonical_bytes,
            sha256=canonical_sha256,
            storage_key=storage_key,
            storage=storage,
        )
    except (BlobStorageError, AttachmentIdentityConflict) as exc:
        if manifest_created:
            try:
                storage.delete(manifest_key)
            except BlobStorageError:
                logger.warning(
                    "DOCUMENT_INTAKE_MANIFEST_CLEANUP_FAILED tenant_id=%s thread_id=%s key=%s",
                    principal.tenant_id,
                    thread_id,
                    manifest_key,
                )
        if isinstance(exc, AttachmentIdentityConflict):
            raise UnifiedDocumentIntakeError("DOCUMENT_INTAKE_IDENTITY_CONFLICT", 409) from exc
        raise UnifiedDocumentIntakeError(str(exc), 503) from exc
    except Exception:
        if manifest_created:
            try:
                storage.delete(manifest_key)
            except BlobStorageError:
                pass
        raise

    try:
        db.add(
            AuditEvent(
                tenant_id=principal.tenant_id,
                actor_id=principal.user_id,
                action="document_intake.paste.ready",
                resource_type="attachment",
                resource_id=persisted.attachment.id,
                outcome="SUCCESS",
                metadata_json={
                    "thread_id": thread_id,
                    "source_kind": "LARGE_PASTE",
                    "source_sha256": source_sha256,
                    "canonical_sha256": canonical_sha256,
                    "source_chars": source_chars,
                    "canonical_chars": canonical.canonical_chars,
                    "sections": len(sections),
                    "chunks": len(chunks),
                    "reused": persisted.reused,
                },
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception(
            "DOCUMENT_INTAKE_AUDIT_WRITE_FAILED tenant_id=%s thread_id=%s attachment_id=%s",
            principal.tenant_id,
            thread_id,
            persisted.attachment.id,
        )

    return PasteIntakeResult(
        attachment=persisted.attachment,
        reused=persisted.reused,
        source_sha256=source_sha256,
        source_chars=source_chars,
        canonical_sha256=canonical_sha256,
        canonical_chars=canonical.canonical_chars,
        sections=len(sections),
        chunks=len(chunks),
        manifest_key=manifest_key,
    )
