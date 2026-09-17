from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import Attachment
from .blob_storage import BlobStorage, BlobStorageError


STORAGE_KEY_UNIQUE_CONSTRAINT = "attachments_storage_key_key"


@dataclass(frozen=True)
class AttachmentPersistResult:
    attachment: Attachment
    created: bool
    reused: bool


class AttachmentIdentityConflict(RuntimeError):
    """Existing storage identity does not match the current logical upload."""


def _find_existing(
    db: Session,
    *,
    tenant_id: str,
    thread_id: str,
    storage_key: str,
) -> Attachment | None:
    return db.scalar(
        select(Attachment).where(
            Attachment.tenant_id == tenant_id,
            Attachment.thread_id == thread_id,
            Attachment.storage_key == storage_key,
        )
    )


def _same_logical_attachment(
    row: Attachment,
    *,
    filename: str,
    mime_type: str,
    size_bytes: int,
    sha256: str,
) -> bool:
    return (
        row.filename == filename
        and row.mime_type == mime_type
        and row.size_bytes == size_bytes
        and row.sha256 == sha256
    )


def _constraint_name(exc: IntegrityError) -> str | None:
    original = getattr(exc, "orig", None)
    diag = getattr(original, "diag", None)
    value = getattr(diag, "constraint_name", None) if diag is not None else None
    return value if isinstance(value, str) else None


def is_storage_key_unique_conflict(exc: IntegrityError) -> bool:
    """Recognize only the canonical PostgreSQL unique constraint.

    Generic IntegrityError/UniqueViolation exceptions are intentionally not
    converted into idempotent success.
    """
    return _constraint_name(exc) == STORAGE_KEY_UNIQUE_CONSTRAINT


def _ensure_blob(target: Path, data: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        return
    tmp = target.with_name(target.name + ".uploading")
    tmp.write_bytes(data)
    tmp.replace(target)


def persist_attachment(
    db: Session,
    *,
    tenant_id: str,
    thread_id: str,
    uploaded_by: str,
    filename: str,
    mime_type: str,
    data: bytes,
    sha256: str,
    storage_key: str,
    target: Path | None = None,
    storage: BlobStorage | None = None,
) -> AttachmentPersistResult:
    """Persist one logical attachment idempotently within tenant/thread scope.

    The database unique constraint remains the concurrency arbiter. A duplicate
    caused by a concurrent request is converted to reuse only when the exact
    expected storage-key constraint fired and the canonical row matches the
    same logical attachment.
    """
    existing = _find_existing(
        db,
        tenant_id=tenant_id,
        thread_id=thread_id,
        storage_key=storage_key,
    )
    if existing is not None:
        if not _same_logical_attachment(
            existing,
            filename=filename,
            mime_type=mime_type,
            size_bytes=len(data),
            sha256=sha256,
        ):
            raise AttachmentIdentityConflict("ATTACHMENT_IDENTITY_CONFLICT")
        if storage is not None:
            storage.put_if_absent(storage_key, data, content_type=mime_type)
        elif target is not None:
            _ensure_blob(target, data)
        else:
            raise BlobStorageError("STORAGE_BACKEND_REQUIRED")
        return AttachmentPersistResult(existing, created=False, reused=True)

    target_existed_before = target.exists() if target is not None else False
    blob_created = False
    if storage is not None:
        blob_created = storage.put_if_absent(storage_key, data, content_type=mime_type)
    elif target is not None:
        _ensure_blob(target, data)
        blob_created = not target_existed_before
    else:
        raise BlobStorageError("STORAGE_BACKEND_REQUIRED")

    row = Attachment(
        tenant_id=tenant_id,
        thread_id=thread_id,
        uploaded_by=uploaded_by,
        filename=filename,
        mime_type=mime_type,
        size_bytes=len(data),
        sha256=sha256,
        storage_key=storage_key,
    )
    db.add(row)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()

        if is_storage_key_unique_conflict(exc):
            canonical = _find_existing(
                db,
                tenant_id=tenant_id,
                thread_id=thread_id,
                storage_key=storage_key,
            )
            if canonical is not None and _same_logical_attachment(
                canonical,
                filename=filename,
                mime_type=mime_type,
                size_bytes=len(data),
                sha256=sha256,
            ):
                return AttachmentPersistResult(
                    canonical,
                    created=False,
                    reused=True,
                )

        # Cleanup only when this request created the blob and no canonical
        # database row references the same scoped storage key.
        canonical = _find_existing(
            db,
            tenant_id=tenant_id,
            thread_id=thread_id,
            storage_key=storage_key,
        )
        if canonical is None and blob_created:
            if storage is not None:
                try:
                    storage.delete(storage_key)
                except BlobStorageError:
                    pass
            elif target is not None:
                target.unlink(missing_ok=True)
        raise

    return AttachmentPersistResult(row, created=True, reused=False)
