from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import logging
import uuid
from pathlib import Path

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import Principal
from ..models import (
    AuditEvent,
    KnowledgeDocument,
    KnowledgeScope,
    KnowledgeStatus,
    KnowledgeStorageCleanup,
)
from .blob_storage import BlobStorage, BlobStorageError
from .knowledge_policy import (
    assert_can_delete,
    assert_can_publish,
    assert_can_revoke,
    assert_can_supersede,
    assert_document_visible_for_management,
    assert_list_allowed,
    assert_upload_allowed,
    is_platform_owner,
    is_tenant_admin,
    normalize_scope,
)


_ALLOWED_PURPOSES = {"chat", "team", "realtime"}
logger = logging.getLogger("patroai.knowledge.repository")


class KnowledgeRepositoryError(RuntimeError):
    def __init__(self, code: str, status_code: int = 409):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_purposes(values: list[str] | tuple[str, ...] | None) -> list[str]:
    raw = list(values or ["chat", "team", "realtime"])
    result: list[str] = []
    for item in raw:
        value = str(item or "").strip().lower()
        if value not in _ALLOWED_PURPOSES:
            raise KnowledgeRepositoryError("KNOWLEDGE_PURPOSE_INVALID", 422)
        if value not in result:
            result.append(value)
    if not result:
        raise KnowledgeRepositoryError("KNOWLEDGE_PURPOSE_REQUIRED", 422)
    return result


def _management_visibility_clause(principal: Principal):
    """Encode management visibility in SQL, not only in post-fetch policy."""
    clauses = [
        and_(
            KnowledgeDocument.scope == KnowledgeScope.personal.value,
            KnowledgeDocument.tenant_id == principal.tenant_id,
            KnowledgeDocument.owner_user_id == principal.user_id,
        )
    ]
    if is_tenant_admin(principal):
        clauses.append(
            and_(
                KnowledgeDocument.scope == KnowledgeScope.institutional.value,
                KnowledgeDocument.tenant_id == principal.tenant_id,
            )
        )
    if is_platform_owner(principal):
        clauses.append(
            and_(
                KnowledgeDocument.scope == KnowledgeScope.platform.value,
                KnowledgeDocument.tenant_id.is_(None),
            )
        )
    return or_(*clauses)


def _queue_storage_cleanup(
    db: Session,
    *,
    storage_key: str,
    reason: str,
    tenant_id: str | None,
    knowledge_id: str | None,
    last_error: str | None,
) -> None:
    """Best-effort durable record for an orphan blob cleanup.

    This function is intentionally metadata-only. If the database itself is
    unavailable, structured logging remains the final fallback and the blob is
    left intact rather than risking deletion of data that may already be durable.
    """
    try:
        task = db.scalar(
            select(KnowledgeStorageCleanup).where(
                KnowledgeStorageCleanup.storage_key == storage_key
            )
        )
        current = utcnow()
        if task is None:
            task = KnowledgeStorageCleanup(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                knowledge_id=knowledge_id,
                storage_key=storage_key,
                reason=reason[:80],
                status="PENDING",
                attempts=0,
                last_error=(last_error or "")[:160] or None,
                created_at=current,
                updated_at=current,
            )
            db.add(task)
        else:
            task.reason = reason[:80]
            task.status = "PENDING"
            task.last_error = (last_error or "")[:160] or None
            task.updated_at = current
        db.commit()
        logger.warning(
            "KNOWLEDGE_STORAGE_CLEANUP_QUEUED storage_key=%s reason=%s knowledge_id=%s",
            storage_key,
            reason,
            knowledge_id or "",
        )
    except Exception:
        db.rollback()
        logger.exception(
            "KNOWLEDGE_STORAGE_CLEANUP_QUEUE_FAILED storage_key=%s reason=%s knowledge_id=%s",
            storage_key,
            reason,
            knowledge_id or "",
        )


def _delete_blob_or_enqueue(
    db: Session,
    *,
    storage: BlobStorage,
    storage_key: str,
    reason: str,
    tenant_id: str | None,
    knowledge_id: str | None,
) -> bool:
    try:
        storage.delete(storage_key)
        return True
    except BlobStorageError as exc:
        _queue_storage_cleanup(
            db,
            storage_key=storage_key,
            reason=reason,
            tenant_id=tenant_id,
            knowledge_id=knowledge_id,
            last_error=str(exc),
        )
        return False


def _resolve_blob_after_failed_commit(
    db: Session,
    *,
    storage: BlobStorage,
    storage_key: str,
    row_id: str,
    tenant_id: str | None,
    reason: str,
) -> str:
    """Resolve an ambiguous DB commit without risking a durable row's blob.

    Returns ``PERSISTED`` when the generated row is visible after rollback,
    ``ABSENT`` when absence is proven and the blob was deleted/queued, and
    ``UNKNOWN`` when database state cannot be established. UNKNOWN deliberately
    keeps the blob intact; an orphan is safer than a durable knowledge row that
    points to missing storage.
    """
    try:
        persisted_id = db.scalar(
            select(KnowledgeDocument.id).where(KnowledgeDocument.id == row_id)
        )
    except Exception:
        db.rollback()
        logger.exception(
            "KNOWLEDGE_COMMIT_OUTCOME_UNKNOWN storage_key=%s knowledge_id=%s reason=%s",
            storage_key,
            row_id,
            reason,
        )
        return "UNKNOWN"

    if persisted_id:
        logger.warning(
            "KNOWLEDGE_COMMIT_OUTCOME_PERSISTED storage_key=%s knowledge_id=%s reason=%s",
            storage_key,
            row_id,
            reason,
        )
        return "PERSISTED"

    _delete_blob_or_enqueue(
        db,
        storage=storage,
        storage_key=storage_key,
        reason=reason,
        tenant_id=tenant_id,
        knowledge_id=row_id,
    )
    return "ABSENT"

def process_storage_cleanup_tasks(
    db: Session,
    *,
    storage: BlobStorage,
    limit: int = 50,
) -> dict[str, int]:
    """Process the durable orphan-blob cleanup queue.

    Intended for an explicit maintenance job or controlled operational command;
    it is never invoked from a GET/read path.
    """
    bounded_limit = max(1, min(int(limit), 500))
    tasks = list(
        db.scalars(
            select(KnowledgeStorageCleanup)
            .where(KnowledgeStorageCleanup.status == "PENDING")
            .order_by(KnowledgeStorageCleanup.created_at.asc())
            .limit(bounded_limit)
            .with_for_update()
        ).all()
    )
    processed = 0
    failed = 0
    for task in tasks:
        task.attempts = int(task.attempts or 0) + 1
        task.updated_at = utcnow()
        try:
            storage.delete(task.storage_key)
            task.status = "DONE"
            task.last_error = None
            processed += 1
        except BlobStorageError as exc:
            task.status = "PENDING"
            task.last_error = str(exc)[:160]
            failed += 1
    db.commit()
    return {"processed": processed, "failed": failed, "selected": len(tasks)}


def _audit(
    db: Session,
    *,
    tenant_id: str | None,
    actor_id: str | None,
    action: str,
    document: KnowledgeDocument,
    outcome: str = "success",
    extra: dict[str, object] | None = None,
) -> None:
    metadata: dict[str, object] = {
        "knowledge_id": document.id,
        "logical_id": document.logical_document_id,
        "version": int(document.version),
        "scope": document.scope,
        "status": document.status,
    }
    for key, value in (extra or {}).items():
        if key in {
            "execution_id",
            "purpose",
            "agent_id",
            "thread_id",
            "previous_knowledge_id",
            "new_knowledge_id",
        } and (value is None or isinstance(value, (str, int, float, bool))):
            metadata[key] = value
    db.add(
        AuditEvent(
            tenant_id=tenant_id,
            actor_id=actor_id,
            action=action,
            resource_type="knowledge",
            resource_id=document.id,
            outcome=outcome,
            metadata_json=metadata,
        )
    )


def audit_knowledge_used(
    db: Session,
    *,
    document: KnowledgeDocument,
    execution_tenant_id: str,
    user_id: str,
    execution_id: str,
    purpose: str,
    thread_id: str | None,
    agent_id: str | None,
) -> None:
    """Persist provenance without raw document content or prompt material."""
    _audit(
        db,
        tenant_id=execution_tenant_id,
        actor_id=user_id,
        action="knowledge.used",
        document=document,
        extra={
            "execution_id": execution_id,
            "purpose": purpose,
            "thread_id": thread_id,
            "agent_id": agent_id,
        },
    )


def document_payload(document: KnowledgeDocument) -> dict[str, object]:
    return {
        "id": document.id,
        "logical_document_id": document.logical_document_id,
        "version": int(document.version),
        "scope": document.scope,
        "agent_id": document.agent_id,
        "title": document.title,
        "filename": document.source_filename,
        "mime_type": document.mime_type,
        "size_bytes": int(document.size_bytes),
        "sha256": document.sha256,
        "classification": document.classification,
        "allowed_purposes": list(document.allowed_purposes or []),
        "status": document.status,
        "effective_from": document.effective_from,
        "expires_at": document.expires_at,
        "created_by": document.created_by,
        "approved_by": document.approved_by,
        "supersedes_id": document.supersedes_id,
        "created_at": document.created_at,
        "updated_at": document.updated_at,
    }


def _storage_key(
    *,
    scope: str,
    tenant_id: str | None,
    logical_document_id: str,
    version: int,
    digest: str,
    filename: str,
) -> str:
    namespace = tenant_id or "global"
    return (
        f"knowledge/{scope.lower()}/{namespace}/{logical_document_id}/"
        f"v{version}/{digest}-{filename}"
    )


def create_uploaded_document_from_file(
    db: Session,
    *,
    principal: Principal,
    scope: str,
    title: str,
    filename: str,
    mime_type: str,
    source_path: Path,
    size_bytes: int,
    digest: str,
    classification: str,
    allowed_purposes: list[str] | tuple[str, ...] | None,
    agent_id: str | None,
    expires_at: datetime | None,
    storage: BlobStorage,
) -> KnowledgeDocument:
    """Persist a knowledge source from a local staging file without full buffering."""
    scope = normalize_scope(scope)
    assert_upload_allowed(scope, principal)
    purposes = normalize_purposes(allowed_purposes)
    logical_id = str(uuid.uuid4())
    row_id = str(uuid.uuid4())
    status = (
        KnowledgeStatus.active.value
        if scope == KnowledgeScope.personal.value
        else KnowledgeStatus.draft.value
    )
    tenant_id = None if scope == KnowledgeScope.platform.value else principal.tenant_id
    owner_user_id = principal.user_id if scope == KnowledgeScope.personal.value else None
    current = utcnow()
    storage_key = _storage_key(
        scope=scope,
        tenant_id=tenant_id,
        logical_document_id=logical_id,
        version=1,
        digest=digest,
        filename=filename,
    )
    created_blob = storage.put_file_if_absent(
        storage_key,
        source_path,
        content_type=mime_type,
    )
    if not created_blob:
        raise KnowledgeRepositoryError("KNOWLEDGE_STORAGE_KEY_CONFLICT")

    row = KnowledgeDocument(
        id=row_id,
        tenant_id=tenant_id,
        owner_user_id=owner_user_id,
        scope=scope,
        agent_id=agent_id,
        title=title,
        source_filename=filename,
        mime_type=mime_type,
        size_bytes=size_bytes,
        sha256=digest,
        storage_key=storage_key,
        classification=classification,
        allowed_purposes=purposes,
        logical_document_id=logical_id,
        version=1,
        status=status,
        effective_from=current if status == KnowledgeStatus.active.value else None,
        expires_at=expires_at,
        created_by=principal.user_id,
        approved_by=principal.user_id if status == KnowledgeStatus.active.value else None,
        supersedes_id=None,
        created_at=current,
        updated_at=current,
    )
    db.add(row)
    _audit(
        db,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="knowledge.uploaded",
        document=row,
    )
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        outcome = _resolve_blob_after_failed_commit(
            db,
            storage=storage,
            storage_key=storage_key,
            row_id=row_id,
            tenant_id=tenant_id,
            reason="knowledge_create_commit_failed",
        )
        if outcome == "PERSISTED":
            persisted = db.get(KnowledgeDocument, row_id)
            if persisted is not None:
                return persisted
        raise KnowledgeRepositoryError("KNOWLEDGE_CREATE_FAILED") from exc
    return row


def create_uploaded_document(
    db: Session,
    *,
    principal: Principal,
    scope: str,
    title: str,
    filename: str,
    mime_type: str,
    data: bytes,
    digest: str | None,
    classification: str,
    allowed_purposes: list[str] | tuple[str, ...] | None,
    agent_id: str | None,
    expires_at: datetime | None,
    storage: BlobStorage,
) -> KnowledgeDocument:
    scope = normalize_scope(scope)
    assert_upload_allowed(scope, principal)
    purposes = normalize_purposes(allowed_purposes)
    digest = digest or hashlib.sha256(data).hexdigest()
    logical_id = str(uuid.uuid4())
    row_id = str(uuid.uuid4())
    status = (
        KnowledgeStatus.active.value
        if scope == KnowledgeScope.personal.value
        else KnowledgeStatus.draft.value
    )
    tenant_id = None if scope == KnowledgeScope.platform.value else principal.tenant_id
    owner_user_id = principal.user_id if scope == KnowledgeScope.personal.value else None
    current = utcnow()
    storage_key = _storage_key(
        scope=scope,
        tenant_id=tenant_id,
        logical_document_id=logical_id,
        version=1,
        digest=digest,
        filename=filename,
    )
    created_blob = storage.put_if_absent(storage_key, data, content_type=mime_type)
    if not created_blob:
        raise KnowledgeRepositoryError("KNOWLEDGE_STORAGE_KEY_CONFLICT")

    row = KnowledgeDocument(
        id=row_id,
        tenant_id=tenant_id,
        owner_user_id=owner_user_id,
        scope=scope,
        agent_id=agent_id or None,
        title=title,
        source_filename=filename,
        mime_type=mime_type,
        size_bytes=len(data),
        sha256=digest,
        storage_key=storage_key,
        classification=classification,
        allowed_purposes=purposes,
        logical_document_id=logical_id,
        version=1,
        status=status,
        effective_from=current if status == KnowledgeStatus.active.value else None,
        expires_at=expires_at,
        created_by=principal.user_id,
        approved_by=principal.user_id if status == KnowledgeStatus.active.value else None,
        created_at=current,
        updated_at=current,
    )
    db.add(row)
    _audit(
        db,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="knowledge.created",
        document=row,
    )
    if status == KnowledgeStatus.active.value:
        _audit(
            db,
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action="knowledge.published",
            document=row,
        )

    # Critical boundary: after commit succeeds there is no storage compensation.
    # SessionLocal uses expire_on_commit=False, so a post-commit refresh is not
    # required to return fields populated by this function.
    try:
        db.commit()
    except Exception:
        db.rollback()
        outcome = _resolve_blob_after_failed_commit(
            db,
            storage=storage,
            storage_key=storage_key,
            row_id=row_id,
            tenant_id=tenant_id,
            reason="CREATE_COMMIT_FAILED",
        )
        if outcome == "PERSISTED":
            return db.get(KnowledgeDocument, row_id) or row
        raise
    return row

def get_managed_document(
    db: Session,
    *,
    document_id: str,
    principal: Principal,
    for_update: bool = False,
) -> KnowledgeDocument:
    stmt = select(KnowledgeDocument).where(
        KnowledgeDocument.id == document_id,
        _management_visibility_clause(principal),
    )
    if for_update:
        stmt = stmt.with_for_update()
    document = db.scalar(stmt)
    if document is None:
        from .knowledge_policy import KnowledgePolicyError
        raise KnowledgePolicyError("KNOWLEDGE_NOT_FOUND", 404)
    # Defense in depth: SQL scoping is authoritative for data access, while
    # policy remains the semantic authorization gate.
    assert_document_visible_for_management(document, principal)
    return document

def list_documents(
    db: Session,
    *,
    principal: Principal,
    scope: str,
) -> list[KnowledgeDocument]:
    scope = normalize_scope(scope)
    assert_list_allowed(scope, principal)
    stmt = select(KnowledgeDocument).where(KnowledgeDocument.scope == scope)
    if scope == KnowledgeScope.personal.value:
        stmt = stmt.where(
            KnowledgeDocument.tenant_id == principal.tenant_id,
            KnowledgeDocument.owner_user_id == principal.user_id,
        )
    elif scope == KnowledgeScope.institutional.value:
        stmt = stmt.where(KnowledgeDocument.tenant_id == principal.tenant_id)
    else:
        stmt = stmt.where(KnowledgeDocument.tenant_id.is_(None))
    return list(
        db.scalars(
            stmt.order_by(
                KnowledgeDocument.logical_document_id.asc(),
                KnowledgeDocument.version.desc(),
                KnowledgeDocument.created_at.desc(),
            )
        ).all()
    )


def list_versions(
    db: Session,
    *,
    principal: Principal,
    logical_document_id: str,
) -> list[KnowledgeDocument]:
    rows = list(
        db.scalars(
            select(KnowledgeDocument)
            .where(
                KnowledgeDocument.logical_document_id == logical_document_id,
                _management_visibility_clause(principal),
            )
            .order_by(KnowledgeDocument.version.asc())
        ).all()
    )
    if not rows:
        from .knowledge_policy import KnowledgePolicyError
        raise KnowledgePolicyError("KNOWLEDGE_NOT_FOUND", 404)
    for row in rows:
        assert_document_visible_for_management(row, principal)
    return rows

def publish_document(
    db: Session,
    *,
    principal: Principal,
    document_id: str,
) -> KnowledgeDocument:
    document = get_managed_document(
        db, document_id=document_id, principal=principal, for_update=True
    )
    assert_can_publish(document, principal)
    current = utcnow()
    document.status = KnowledgeStatus.active.value
    document.effective_from = current
    document.approved_by = principal.user_id
    document.updated_at = current
    _audit(
        db,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="knowledge.published",
        document=document,
    )
    db.commit()
    db.refresh(document)
    return document


def revoke_document(
    db: Session,
    *,
    principal: Principal,
    document_id: str,
) -> KnowledgeDocument:
    document = get_managed_document(
        db, document_id=document_id, principal=principal, for_update=True
    )
    assert_can_revoke(document, principal)
    document.status = KnowledgeStatus.revoked.value
    document.updated_at = utcnow()
    _audit(
        db,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="knowledge.revoked",
        document=document,
    )
    db.commit()
    db.refresh(document)
    return document


def supersede_document_from_file(
    db: Session,
    *,
    principal: Principal,
    document_id: str,
    title: str | None,
    filename: str,
    mime_type: str,
    source_path: Path,
    size_bytes: int,
    digest: str,
    classification: str | None,
    allowed_purposes: list[str] | tuple[str, ...] | None,
    agent_id: str | None,
    expires_at: datetime | None,
    storage: BlobStorage,
) -> KnowledgeDocument:
    current_document = get_managed_document(
        db, document_id=document_id, principal=principal
    )
    assert_can_supersede(current_document, principal)
    if current_document.status != KnowledgeStatus.active.value:
        raise KnowledgeRepositoryError("KNOWLEDGE_SUPERSEDE_REQUIRES_ACTIVE")
    purposes = normalize_purposes(
        allowed_purposes
        if allowed_purposes is not None
        else list(current_document.allowed_purposes or [])
    )
    new_version = int(current_document.version) + 1
    row_id = str(uuid.uuid4())
    current = utcnow()
    storage_key = _storage_key(
        scope=current_document.scope,
        tenant_id=current_document.tenant_id,
        logical_document_id=current_document.logical_document_id,
        version=new_version,
        digest=digest,
        filename=filename,
    )
    created_blob = storage.put_file_if_absent(
        storage_key,
        source_path,
        content_type=mime_type,
    )
    if not created_blob:
        raise KnowledgeRepositoryError("KNOWLEDGE_STORAGE_KEY_CONFLICT")

    replacement = KnowledgeDocument(
        id=row_id,
        tenant_id=current_document.tenant_id,
        owner_user_id=current_document.owner_user_id,
        scope=current_document.scope,
        agent_id=agent_id if agent_id is not None else current_document.agent_id,
        title=title or current_document.title,
        source_filename=filename,
        mime_type=mime_type,
        size_bytes=size_bytes,
        sha256=digest,
        storage_key=storage_key,
        classification=classification or current_document.classification,
        allowed_purposes=purposes,
        logical_document_id=current_document.logical_document_id,
        version=new_version,
        status=KnowledgeStatus.active.value,
        effective_from=current,
        expires_at=expires_at if expires_at is not None else current_document.expires_at,
        created_by=principal.user_id,
        approved_by=principal.user_id,
        supersedes_id=current_document.id,
        created_at=current,
        updated_at=current,
    )
    current_document.status = KnowledgeStatus.superseded.value
    current_document.updated_at = current
    db.add(replacement)
    _audit(
        db,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="knowledge.superseded",
        document=replacement,
        extra={"previous_knowledge_id": current_document.id},
    )
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        outcome = _resolve_blob_after_failed_commit(
            db,
            storage=storage,
            storage_key=storage_key,
            row_id=row_id,
            tenant_id=current_document.tenant_id,
            reason="knowledge_supersede_commit_failed",
        )
        if outcome == "PERSISTED":
            persisted = db.get(KnowledgeDocument, row_id)
            if persisted is not None:
                return persisted
        raise KnowledgeRepositoryError("KNOWLEDGE_SUPERSEDE_FAILED") from exc
    return replacement


def supersede_document(
    db: Session,
    *,
    principal: Principal,
    document_id: str,
    title: str | None,
    filename: str,
    mime_type: str,
    data: bytes,
    digest: str | None,
    classification: str | None,
    allowed_purposes: list[str] | tuple[str, ...] | None,
    agent_id: str | None,
    expires_at: datetime | None,
    storage: BlobStorage,
) -> KnowledgeDocument:
    old = get_managed_document(
        db, document_id=document_id, principal=principal, for_update=True
    )
    assert_can_supersede(old, principal)
    tenant_id = old.tenant_id
    digest = digest or hashlib.sha256(data).hexdigest()
    version = int(old.version) + 1
    purposes = (
        normalize_purposes(allowed_purposes)
        if allowed_purposes is not None
        else list(old.allowed_purposes or ["chat", "team", "realtime"])
    )
    new_id = str(uuid.uuid4())
    storage_key = _storage_key(
        scope=old.scope,
        tenant_id=tenant_id,
        logical_document_id=old.logical_document_id,
        version=version,
        digest=digest,
        filename=filename,
    )
    current = utcnow()
    created_blob = storage.put_if_absent(storage_key, data, content_type=mime_type)
    if not created_blob:
        raise KnowledgeRepositoryError("KNOWLEDGE_STORAGE_KEY_CONFLICT")

    new = KnowledgeDocument(
        id=new_id,
        tenant_id=tenant_id,
        owner_user_id=old.owner_user_id,
        scope=old.scope,
        agent_id=agent_id if agent_id is not None else old.agent_id,
        title=(title or old.title).strip(),
        source_filename=filename,
        mime_type=mime_type,
        size_bytes=len(data),
        sha256=digest,
        storage_key=storage_key,
        classification=(classification or old.classification),
        allowed_purposes=purposes,
        logical_document_id=old.logical_document_id,
        version=version,
        status=KnowledgeStatus.active.value,
        effective_from=current,
        expires_at=expires_at if expires_at is not None else old.expires_at,
        created_by=principal.user_id,
        approved_by=principal.user_id,
        supersedes_id=old.id,
        created_at=current,
        updated_at=current,
    )
    old.status = KnowledgeStatus.superseded.value
    old.updated_at = current
    db.add(new)
    _audit(
        db,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="knowledge.superseded",
        document=old,
        extra={"new_knowledge_id": new.id},
    )
    _audit(
        db,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="knowledge.published",
        document=new,
        extra={"previous_knowledge_id": old.id},
    )

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        outcome = _resolve_blob_after_failed_commit(
            db,
            storage=storage,
            storage_key=storage_key,
            row_id=new_id,
            tenant_id=tenant_id,
            reason="SUPERSEDE_VERSION_CONFLICT",
        )
        if outcome == "PERSISTED":
            return db.get(KnowledgeDocument, new_id) or new
        raise KnowledgeRepositoryError("KNOWLEDGE_VERSION_CONFLICT", 409) from exc
    except Exception:
        db.rollback()
        outcome = _resolve_blob_after_failed_commit(
            db,
            storage=storage,
            storage_key=storage_key,
            row_id=new_id,
            tenant_id=tenant_id,
            reason="SUPERSEDE_COMMIT_FAILED",
        )
        if outcome == "PERSISTED":
            return db.get(KnowledgeDocument, new_id) or new
        raise
    return new

def delete_document(
    db: Session,
    *,
    principal: Principal,
    document_id: str,
    storage: BlobStorage,
) -> None:
    document = get_managed_document(
        db, document_id=document_id, principal=principal, for_update=True
    )
    assert_can_delete(document, principal)
    storage_key = document.storage_key
    tenant_id = document.tenant_id
    knowledge_id = document.id
    _audit(
        db,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="knowledge.deleted",
        document=document,
    )
    db.delete(document)
    db.commit()

    # Database state is authoritative. A storage deletion failure must not
    # resurrect an inaccessible row or turn a successful logical delete into an
    # inconsistent retry. Persist a cleanup task instead.
    _delete_blob_or_enqueue(
        db,
        storage=storage,
        storage_key=storage_key,
        reason="DELETE_POST_COMMIT_ORPHAN",
        tenant_id=tenant_id,
        knowledge_id=knowledge_id,
    )

