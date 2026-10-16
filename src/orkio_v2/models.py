import enum, uuid
from datetime import datetime, timezone
from decimal import Decimal
from sqlalchemy import String, DateTime, ForeignKey, Boolean, Integer, Text, UniqueConstraint, CheckConstraint, Index, JSON, Numeric, text, event, func
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base

def uid() -> str: return str(uuid.uuid4())
def now() -> datetime: return datetime.now(timezone.utc)

class ThreadRole(str, enum.Enum):
    owner="owner"; moderator="moderator"; participant="participant"; viewer="viewer"
class InviteStatus(str, enum.Enum):
    pending="pending"; accepted="accepted"; revoked="revoked"; expired="expired"

class PlatformInvitationState(str, enum.Enum):
    pending="PENDING"; accepted="ACCEPTED"; revoked="REVOKED"; expired="EXPIRED"

class PlatformInvitationDeliveryStatus(str, enum.Enum):
    pending="PENDING"; accepted_by_provider="ACCEPTED_BY_PROVIDER"; delivery_failed="DELIVERY_FAILED"
class ProposalStatus(str, enum.Enum):
    draft="draft"; awaiting_approval="awaiting_approval"; approved_for_dry_run="approved_for_dry_run"; rejected="rejected"

class Tenant(Base):
    __tablename__="tenants"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class User(Base):
    __tablename__="users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    external_subject: Mapped[str] = mapped_column(String(255), unique=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    display_name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

# Premium identity invariant: native/application code normalizes emails on write,
# while the database enforces uniqueness on the normalized representation.
# The Alembic migration performs a duplicate preflight before creating this index.
Index("uq_users_email_normalized", func.lower(func.trim(User.email)), unique=True)

class Membership(Base):
    __tablename__="memberships"
    __table_args__=(UniqueConstraint("tenant_id","user_id", name="uq_membership_tenant_user"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(40), default="member")
    active: Mapped[bool] = mapped_column(Boolean, default=True)

class NativeCredential(Base):
    __tablename__ = "native_credentials"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(512))
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class NativeSession(Base):
    __tablename__ = "native_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    session_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(16), index=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    user_agent: Mapped[str] = mapped_column(String(240), default="")
    ip_prefix: Mapped[str] = mapped_column(String(80), default="")
    previous_session_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    rotation_grace_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    authenticated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reauthenticated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class NativePasswordReset(Base):
    __tablename__ = "native_password_resets"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(16), index=True)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class Thread(Base):
    __tablename__="threads"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(240), default="Nova conversa")
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class ThreadParticipant(Base):
    __tablename__="thread_participants"
    __table_args__=(UniqueConstraint("thread_id","user_id", name="uq_thread_participant"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    thread_id: Mapped[str] = mapped_column(ForeignKey("threads.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    thread_role: Mapped[str] = mapped_column(String(30), default=ThreadRole.participant.value)
    membership_type: Mapped[str] = mapped_column(String(30), default="tenant_member")
    history_access: Mapped[str] = mapped_column(String(30), default="from_join")
    # Null represents the pre-migration legacy grant: Josué only for non-admins.
    allowed_agent_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    # NULL inherits pre-015 behavior; explicit False revokes the capability.
    can_read_messages: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    can_write_messages: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    can_view_attachments: Mapped[bool] = mapped_column(Boolean, default=False)
    can_download_artifacts: Mapped[bool] = mapped_column(Boolean, default=False)
    can_upload_files: Mapped[bool] = mapped_column(Boolean, default=False)
    can_generate_artifacts: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    # NULL preserves unlimited access for grants created before migration 016.
    access_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class ThreadInvitation(Base):
    __tablename__="thread_invitations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    thread_id: Mapped[str] = mapped_column(ForeignKey("threads.id", ondelete="CASCADE"), index=True)
    invited_email: Mapped[str] = mapped_column(String(320), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(12))
    thread_role: Mapped[str] = mapped_column(String(30), default=ThreadRole.participant.value)
    history_access: Mapped[str] = mapped_column(String(30), default="from_join")
    # Null represents the pre-migration legacy grant: Josué only for non-admins.
    allowed_agent_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    can_read_messages: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    can_write_messages: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    can_view_attachments: Mapped[bool] = mapped_column(Boolean, default=False)
    can_download_artifacts: Mapped[bool] = mapped_column(Boolean, default=False)
    can_upload_files: Mapped[bool] = mapped_column(Boolean, default=False)
    can_generate_artifacts: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(30), default=InviteStatus.pending.value)
    created_by: Mapped[str] = mapped_column(String(64))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Invitation-token expiry is separate from accepted participant access lifetime.
    # NULL on older invitations preserves their historical unlimited grant.
    access_duration_hours: Mapped[int | None] = mapped_column(Integer, nullable=True)

class PlatformInvitation(Base):
    __tablename__ = "platform_invitations"
    __table_args__ = (
        UniqueConstraint("active_dedupe_key", name="uq_platform_invitation_active_dedupe"),
        CheckConstraint(
            "state IN ('PENDING','ACCEPTED','REVOKED','EXPIRED')",
            name="ck_platform_invitation_state",
        ),
        CheckConstraint(
            "delivery_status IN ('PENDING','ACCEPTED_BY_PROVIDER','DELIVERY_FAILED')",
            name="ck_platform_invitation_delivery_status",
        ),
        Index("ix_platform_invitation_tenant_state", "tenant_id", "state"),
        Index("ix_platform_invitation_tenant_email", "tenant_id", "invited_email"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    invited_email: Mapped[str] = mapped_column(String(320), index=True)
    role: Mapped[str] = mapped_column(String(40), default="member")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    active_dedupe_key: Mapped[str | None] = mapped_column(String(420), nullable=True)
    state: Mapped[str] = mapped_column(
        String(32), default=PlatformInvitationState.pending.value, index=True
    )
    delivery_status: Mapped[str] = mapped_column(
        String(40), default=PlatformInvitationDeliveryStatus.pending.value, index=True
    )
    delivery_generation: Mapped[int] = mapped_column(Integer, default=1)
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(64), index=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    provider_message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    delivery_error_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_delivery_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class PlatformInvitationOutbox(Base):
    __tablename__ = "platform_invitation_outbox"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_platform_invitation_outbox_idempotency"),
        UniqueConstraint(
            "invitation_id", "generation",
            name="uq_platform_invitation_outbox_generation",
        ),
        CheckConstraint(
            "status IN ('PENDING','ACCEPTED_BY_PROVIDER','DELIVERY_FAILED')",
            name="ck_platform_invitation_outbox_status",
        ),
        Index("ix_platform_invitation_outbox_status_created", "status", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    invitation_id: Mapped[str] = mapped_column(
        ForeignKey("platform_invitations.id", ondelete="CASCADE"), index=True
    )
    generation: Mapped[int] = mapped_column(Integer)
    idempotency_key: Mapped[str] = mapped_column(String(180))
    status: Mapped[str] = mapped_column(
        String(40), default=PlatformInvitationDeliveryStatus.pending.value, index=True
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    provider_message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Message(Base):
    __tablename__="messages"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    thread_id: Mapped[str] = mapped_column(ForeignKey("threads.id", ondelete="CASCADE"), index=True)
    author_type: Mapped[str] = mapped_column(String(30))
    author_id: Mapped[str] = mapped_column(String(64))
    agent_name: Mapped[str | None] = mapped_column(String(80), nullable=True)
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Attachment(Base):
    __tablename__="attachments"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    thread_id: Mapped[str] = mapped_column(String(64), index=True)
    uploaded_by: Mapped[str] = mapped_column(String(64))
    filename: Mapped[str] = mapped_column(String(255))
    mime_type: Mapped[str] = mapped_column(String(120))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    storage_key: Mapped[str] = mapped_column(String(500), unique=True)
    status: Mapped[str] = mapped_column(String(30), default="ready")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class KnowledgeScope(str, enum.Enum):
    personal = "PERSONAL"
    institutional = "INSTITUTIONAL"
    platform = "PLATFORM"


class KnowledgeStatus(str, enum.Enum):
    draft = "DRAFT"
    active = "ACTIVE"
    superseded = "SUPERSEDED"
    revoked = "REVOKED"


class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"
    __table_args__ = (
        UniqueConstraint(
            "logical_document_id",
            "version",
            name="uq_knowledge_document_logical_version",
        ),
        CheckConstraint(
            "scope IN ('PERSONAL','INSTITUTIONAL','PLATFORM')",
            name="ck_knowledge_scope_valid",
        ),
        CheckConstraint(
            "status IN ('DRAFT','ACTIVE','SUPERSEDED','REVOKED')",
            name="ck_knowledge_status_valid",
        ),
        CheckConstraint(
            "version >= 1",
            name="ck_knowledge_version_positive",
        ),
        CheckConstraint(
            "("
            "(scope = 'PLATFORM' AND tenant_id IS NULL AND owner_user_id IS NULL) OR "
            "(scope = 'INSTITUTIONAL' AND tenant_id IS NOT NULL AND owner_user_id IS NULL) OR "
            "(scope = 'PERSONAL' AND tenant_id IS NOT NULL AND owner_user_id IS NOT NULL)"
            ")",
            name="ck_knowledge_scope_tenant_owner",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    # PLATFORM knowledge is global and therefore has tenant_id=NULL. PERSONAL and
    # INSTITUTIONAL rows are always tenant-bound and are enforced by policy/tests.
    tenant_id: Mapped[str | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    owner_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    scope: Mapped[str] = mapped_column(String(24), index=True)
    agent_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(240))
    source_filename: Mapped[str] = mapped_column(String(255))
    mime_type: Mapped[str] = mapped_column(String(120))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    storage_key: Mapped[str] = mapped_column(String(500), unique=True)
    classification: Mapped[str] = mapped_column(String(40), default="internal")
    allowed_purposes: Mapped[list] = mapped_column(
        JSON, default=lambda: ["chat", "team", "realtime"]
    )
    logical_document_id: Mapped[str] = mapped_column(String(64), index=True, default=uid)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(24), index=True)
    effective_from: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_by: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    approved_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    supersedes_id: Mapped[str | None] = mapped_column(
        ForeignKey("knowledge_documents.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, onupdate=now
    )

class KnowledgeDocumentDerivative(Base):
    __tablename__ = "knowledge_document_derivatives"
    __table_args__ = (
        UniqueConstraint("knowledge_id", "kind", name="uq_knowledge_derivative_kind"),
        CheckConstraint(
            "status IN ('PENDING','PROCESSING','READY','PARTIAL','FAILED','OCR_REQUIRED')",
            name="ck_knowledge_derivative_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    knowledge_id: Mapped[str] = mapped_column(
        ForeignKey("knowledge_documents.id", ondelete="CASCADE"), index=True
    )
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(40), default="CANONICAL_MARKDOWN")
    storage_key: Mapped[str | None] = mapped_column(String(500), nullable=True, unique=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="PENDING", index=True)
    extractor: Mapped[str | None] = mapped_column(String(80), nullable=True)
    extractor_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    source_chars: Mapped[int | None] = mapped_column(Integer, nullable=True)
    canonical_chars: Mapped[int | None] = mapped_column(Integer, nullable=True)
    page_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    warnings_json: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, onupdate=now
    )


class KnowledgeDocumentSection(Base):
    __tablename__ = "knowledge_document_sections"
    __table_args__ = (
        UniqueConstraint("knowledge_id", "ordinal", name="uq_knowledge_section_ordinal"),
        CheckConstraint("level >= 0", name="ck_knowledge_section_level_nonnegative"),
        CheckConstraint("byte_end >= byte_start", name="ck_knowledge_section_byte_range"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    knowledge_id: Mapped[str] = mapped_column(
        ForeignKey("knowledge_documents.id", ondelete="CASCADE"), index=True
    )
    derivative_id: Mapped[str] = mapped_column(
        ForeignKey("knowledge_document_derivatives.id", ondelete="CASCADE"), index=True
    )
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    parent_section_id: Mapped[str | None] = mapped_column(
        ForeignKey("knowledge_document_sections.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    ordinal: Mapped[int] = mapped_column(Integer)
    heading: Mapped[str] = mapped_column(String(500))
    level: Mapped[int] = mapped_column(Integer, default=0)
    page_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    page_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    byte_start: Mapped[int] = mapped_column(Integer)
    byte_end: Mapped[int] = mapped_column(Integer)
    estimated_tokens: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class KnowledgeDocumentChunk(Base):
    __tablename__ = "knowledge_document_chunks"
    __table_args__ = (
        UniqueConstraint("knowledge_id", "ordinal", name="uq_knowledge_chunk_ordinal"),
        CheckConstraint("byte_end > byte_start", name="ck_knowledge_chunk_byte_range"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    knowledge_id: Mapped[str] = mapped_column(
        ForeignKey("knowledge_documents.id", ondelete="CASCADE"), index=True
    )
    derivative_id: Mapped[str] = mapped_column(
        ForeignKey("knowledge_document_derivatives.id", ondelete="CASCADE"), index=True
    )
    section_id: Mapped[str | None] = mapped_column(
        ForeignKey("knowledge_document_sections.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    ordinal: Mapped[int] = mapped_column(Integer)
    byte_start: Mapped[int] = mapped_column(Integer)
    byte_end: Mapped[int] = mapped_column(Integer)
    estimated_tokens: Mapped[int] = mapped_column(Integer, default=0)
    text_sha256: Mapped[str] = mapped_column(String(64))
    terms_json: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class KnowledgeDocumentSelection(Base):
    __tablename__ = "knowledge_document_selections"
    __table_args__ = (
        UniqueConstraint(
            "knowledge_id", "tenant_id", "user_id",
            name="uq_knowledge_selection_actor_document"
        ),
        CheckConstraint(
            "mode IN ('MANUAL','AUTO')",
            name="ck_knowledge_selection_mode",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    knowledge_id: Mapped[str] = mapped_column(
        ForeignKey("knowledge_documents.id", ondelete="CASCADE"), index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    mode: Mapped[str] = mapped_column(String(16), default="AUTO")
    section_ids: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, onupdate=now
    )


class KnowledgeStorageCleanup(Base):
    """Durable queue for orphan-blob cleanup after partial storage failures.

    The queue never contains document content, prompts, credentials, or raw
    provider responses. It is operational metadata only.
    """

    __tablename__ = "knowledge_storage_cleanup"
    __table_args__ = (
        UniqueConstraint("storage_key", name="uq_knowledge_storage_cleanup_key"),
        CheckConstraint(
            "status IN ('PENDING','DONE')",
            name="ck_knowledge_storage_cleanup_status",
        ),
        CheckConstraint(
            "attempts >= 0",
            name="ck_knowledge_storage_cleanup_attempts",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    knowledge_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    reason: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, onupdate=now
    )

class Artifact(Base):
    __tablename__="artifacts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    thread_id: Mapped[str] = mapped_column(String(64), index=True)
    created_by: Mapped[str] = mapped_column(String(64))
    filename: Mapped[str] = mapped_column(String(255))
    mime_type: Mapped[str] = mapped_column(String(120))
    storage_key: Mapped[str] = mapped_column(String(500), unique=True)
    sha256: Mapped[str] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class EvolutionProposal(Base):
    __tablename__="evolution_proposals"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(240))
    issue_map: Mapped[dict] = mapped_column(JSON)
    patch_plan: Mapped[dict] = mapped_column(JSON)
    diff_preview: Mapped[str] = mapped_column(Text, default="")
    risk_assessment: Mapped[dict] = mapped_column(JSON)
    rollback_plan: Mapped[dict] = mapped_column(JSON)
    smoke_plan: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(40), default=ProposalStatus.awaiting_approval.value)
    proposal_only: Mapped[bool] = mapped_column(Boolean, default=True)
    write_executed: Mapped[bool] = mapped_column(Boolean, default=False)
    commit_executed: Mapped[bool] = mapped_column(Boolean, default=False)
    merge_executed: Mapped[bool] = mapped_column(Boolean, default=False)
    deploy_executed: Mapped[bool] = mapped_column(Boolean, default=False)
    migration_executed: Mapped[bool] = mapped_column(Boolean, default=False)
    human_approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class AuditEvent(Base):
    __tablename__="audit_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(160), index=True)
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(30))
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)




class BillingCheckout(Base):
    __tablename__ = "billing_checkouts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "user_id", "idempotency_key",
            name="uq_billing_checkout_actor_idempotency",
        ),
        UniqueConstraint(
            "provider", "provider_checkout_id",
            name="uq_billing_checkout_provider_checkout",
        ),
        CheckConstraint(
            "checkout_kind IN ('plan','topup')",
            name="ck_billing_checkout_kind",
        ),
        CheckConstraint(
            "status IN ('pending','paid','failed','expired','cancelled','refunded','chargeback')",
            name="ck_billing_checkout_status",
        ),
        Index("ix_billing_checkout_tenant_user_created", "tenant_id", "user_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    checkout_kind: Mapped[str] = mapped_column(String(16))
    item_code: Mapped[str] = mapped_column(String(80))
    item_name: Mapped[str] = mapped_column(String(200))
    payer_email: Mapped[str] = mapped_column(String(320))
    payer_name: Mapped[str] = mapped_column(String(200))
    company: Mapped[str | None] = mapped_column(String(240), nullable=True)
    currency: Mapped[str] = mapped_column(String(8), default="BRL")
    amount_brl: Mapped[Decimal] = mapped_column(Numeric(18, 2), default=0)
    amount_usd: Mapped[Decimal] = mapped_column(Numeric(18, 4), default=0)
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    provider: Mapped[str] = mapped_column(String(32), default="asaas")
    provider_checkout_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    provider_payment_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    provider_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    callback_success_url: Mapped[str] = mapped_column(String(500))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, onupdate=now
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reversed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class BillingWebhookEvent(Base):
    __tablename__ = "billing_webhook_events"
    __table_args__ = (
        UniqueConstraint(
            "provider", "provider_event_key",
            name="uq_billing_webhook_provider_event",
        ),
        CheckConstraint(
            "status IN ('received','processed','ignored')",
            name="ck_billing_webhook_status",
        ),
        Index("ix_billing_webhook_tenant_created", "tenant_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    checkout_id: Mapped[str | None] = mapped_column(
        ForeignKey("billing_checkouts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    provider: Mapped[str] = mapped_column(String(32), default="asaas")
    provider_event_key: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(80))
    payload_sha256: Mapped[str] = mapped_column(String(64))
    provider_payment_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    provider_checkout_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="received")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class BillingEntitlement(Base):
    __tablename__ = "billing_entitlements"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "user_id",
            name="uq_billing_entitlement_tenant_user",
        ),
        CheckConstraint(
            "status IN ('active','expired','cancelled','refunded','chargeback')",
            name="ck_billing_entitlement_status",
        ),
        Index("ix_billing_entitlement_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    plan_code: Mapped[str] = mapped_column(String(80))
    plan_name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(24), default="active")
    checkout_id: Mapped[str | None] = mapped_column(
        ForeignKey("billing_checkouts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_payment_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, onupdate=now
    )


class BillingTransaction(Base):
    __tablename__ = "billing_transactions"
    __table_args__ = (
        UniqueConstraint(
            "provider", "external_ref", "status", "charge_kind",
            name="uq_billing_transaction_provider_ref_state_kind",
        ),
        CheckConstraint(
            "status IN ('confirmed','refunded','chargeback','void')",
            name="ck_billing_transaction_status",
        ),
        Index("ix_billing_transaction_tenant_created", "tenant_id", "created_at"),
        Index("ix_billing_transaction_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    checkout_id: Mapped[str | None] = mapped_column(
        ForeignKey("billing_checkouts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    provider: Mapped[str] = mapped_column(String(32), default="asaas")
    external_ref: Mapped[str] = mapped_column(String(160))
    plan_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    charge_kind: Mapped[str] = mapped_column(String(32))
    currency: Mapped[str] = mapped_column(String(8), default="USD")
    amount_original: Mapped[Decimal] = mapped_column(Numeric(18, 4), default=0)
    amount_usd: Mapped[Decimal] = mapped_column(Numeric(18, 4), default=0)
    normalized_mrr_usd: Mapped[Decimal] = mapped_column(Numeric(18, 4), default=0)
    status: Mapped[str] = mapped_column(String(24))
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class BillingWallet(Base):
    __tablename__ = "billing_wallets"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "user_id",
            name="uq_billing_wallet_tenant_user",
        ),
        CheckConstraint(
            "status IN ('active','quarantined')",
            name="ck_billing_wallet_status",
        ),
        CheckConstraint(
            "balance_usd >= 0",
            name="ck_billing_wallet_nonnegative_balance",
        ),
        CheckConstraint(
            "quarantined_usd >= 0",
            name="ck_billing_wallet_nonnegative_quarantine",
        ),
        Index("ix_billing_wallet_tenant_updated", "tenant_id", "updated_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    currency: Mapped[str] = mapped_column(String(8), default="USD")
    status: Mapped[str] = mapped_column(String(20), default="active")
    balance_usd: Mapped[Decimal] = mapped_column(Numeric(18, 4), default=0)
    lifetime_credited_usd: Mapped[Decimal] = mapped_column(Numeric(18, 4), default=0)
    lifetime_debited_usd: Mapped[Decimal] = mapped_column(Numeric(18, 4), default=0)
    quarantined_usd: Mapped[Decimal] = mapped_column(Numeric(18, 4), default=0)
    auto_recharge_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_recharge_pack_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    auto_recharge_threshold_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 4), nullable=True)
    low_balance_threshold_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 4), nullable=True, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, onupdate=now
    )


class BillingWalletLedger(Base):
    __tablename__ = "billing_wallet_ledger"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "idempotency_key",
            name="uq_billing_wallet_ledger_tenant_idempotency",
        ),
        CheckConstraint(
            "direction IN ('credit','debit','adjustment')",
            name="ck_billing_wallet_ledger_direction",
        ),
        CheckConstraint(
            "amount_usd >= 0",
            name="ck_billing_wallet_ledger_nonnegative_amount",
        ),
        Index("ix_billing_wallet_ledger_wallet_created", "wallet_id", "created_at"),
        Index("ix_billing_wallet_ledger_tenant_created", "tenant_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    wallet_id: Mapped[str] = mapped_column(
        ForeignKey("billing_wallets.id", ondelete="CASCADE"), index=True
    )
    direction: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(40))
    idempotency_key: Mapped[str] = mapped_column(String(180))
    action_key: Mapped[str | None] = mapped_column(String(120), nullable=True)
    quantity: Mapped[Decimal | None] = mapped_column(Numeric(18, 4), nullable=True)
    unit_price_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 4), nullable=True)
    amount_usd: Mapped[Decimal] = mapped_column(Numeric(18, 4), default=0)
    balance_after_usd: Mapped[Decimal] = mapped_column(Numeric(18, 4), default=0)
    currency: Mapped[str] = mapped_column(String(8), default="USD")
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    external_ref: Mapped[str | None] = mapped_column(String(160), nullable=True)
    related_checkout_id: Mapped[str | None] = mapped_column(
        ForeignKey("billing_checkouts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    related_tx_id: Mapped[str | None] = mapped_column(
        ForeignKey("billing_transactions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditEvidenceRecord(Base):
    """Append-only durable evidence for governed audit capabilities."""

    __tablename__ = "audit_evidence_records"
    __table_args__ = (
        UniqueConstraint(
            "audit_execution_id",
            name="uq_audit_evidence_audit_execution_id",
        ),
        CheckConstraint(
            "capability_decision IN ('ALLOW','DENY')",
            name="ck_audit_evidence_capability_decision",
        ),
        CheckConstraint(
            "status IN ('completed','failed','denied')",
            name="ck_audit_evidence_status",
        ),
        CheckConstraint(
            "length(evidence_sha256) = 64",
            name="ck_audit_evidence_sha256_length",
        ),
        Index(
            "ix_audit_evidence_tenant_created",
            "tenant_id",
            "created_at",
        ),
        Index(
            "ix_audit_evidence_tenant_execution_created",
            "tenant_id",
            "execution_id",
            "created_at",
        ),
        Index(
            "ix_audit_evidence_tenant_capability_created",
            "tenant_id",
            "capability_id",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    audit_execution_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    execution_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    capability_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    capability_version: Mapped[str] = mapped_column(String(40), nullable=False)
    environment: Mapped[str] = mapped_column(String(40), nullable=False)
    deployment_id: Mapped[str] = mapped_column(String(120), nullable=False)
    resolved_agent_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    capability_decision: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    artifact_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    root_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    envelope_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=now,
    )


@event.listens_for(AuditEvidenceRecord, "before_update")
def _reject_audit_evidence_orm_update(mapper, connection, target) -> None:
    raise RuntimeError("AUDIT_EVIDENCE_IMMUTABLE")


@event.listens_for(AuditEvidenceRecord, "before_delete")
def _reject_audit_evidence_orm_delete(mapper, connection, target) -> None:
    raise RuntimeError("AUDIT_EVIDENCE_IMMUTABLE")

class VoiceCatalogEntry(Base):
    __tablename__ = "voice_catalog_entries"
    __table_args__ = (UniqueConstraint("provider_key", "provider_voice_id", name="uq_voice_catalog_provider_voice"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    provider_key: Mapped[str] = mapped_column(String(80), index=True)
    provider_voice_id: Mapped[str] = mapped_column(String(120))
    display_name: Mapped[str] = mapped_column(String(120))
    provider_model: Mapped[str] = mapped_column(String(120))
    source_type: Mapped[str] = mapped_column(String(32), default="BUILT_IN")
    license_label: Mapped[str] = mapped_column(String(160), default="PROVIDER_TERMS")
    cost_class: Mapped[str] = mapped_column(String(40), default="API_USAGE_BILLED")
    provenance_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    catalog_version: Mapped[str] = mapped_column(String(64), default="1")
    supported_locales: Mapped[list] = mapped_column(JSON, default=list)
    delivery_modes: Mapped[list] = mapped_column(JSON, default=list)
    curation_status: Mapped[str] = mapped_column(String(32), default="REVIEW_REQUIRED", index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

class AgentVoiceAssignment(Base):
    """Only ACTIVE + VALIDATED overrides the existing ENV binding."""
    __tablename__ = "agent_voice_assignments"
    __table_args__ = (
        Index("uq_agent_voice_assignment_active", "tenant_id", "agent_slug", "locale", unique=True, postgresql_where=text("active")),
        Index("uq_agent_voice_unique_active", "tenant_id", "voice_catalog_id", unique=True, postgresql_where=text("active")),
        CheckConstraint("assignment_state IN ('DRAFT','ACTIVE','DISABLED')", name="ck_agent_voice_assignment_state"),
        CheckConstraint("validation_status IN ('UNVALIDATED','VALIDATED','FAILED')", name="ck_agent_voice_validation_status"),
        CheckConstraint("NOT (assignment_state = 'ACTIVE' AND validation_status != 'VALIDATED')", name="ck_agent_voice_active_requires_validated"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    agent_slug: Mapped[str] = mapped_column(String(80), index=True)
    voice_catalog_id: Mapped[str] = mapped_column(ForeignKey("voice_catalog_entries.id", ondelete="RESTRICT"), index=True)
    locale: Mapped[str] = mapped_column(String(24), default="pt-BR")
    delivery_modes: Mapped[list] = mapped_column(JSON, default=list)
    presentation_label: Mapped[str] = mapped_column(String(24), default="NAO_DEFINIDA")
    timbre_label: Mapped[str | None] = mapped_column(String(80), nullable=True)
    energy_label: Mapped[str | None] = mapped_column(String(80), nullable=True)
    assignment_state: Mapped[str] = mapped_column(String(24), default="DRAFT", index=True)
    validation_status: Mapped[str] = mapped_column(String(24), default="UNVALIDATED", index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    updated_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class AgentStudioVersion(Base):
    """Tenant-scoped, versioned control-plane configuration for agents.

    Runtime activation intentionally remains fail-closed until the canonical
    agent registry becomes tenant-aware.
    """

    __tablename__ = "agent_studio_versions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "agent_slug",
            "version",
            name="uq_agent_studio_tenant_slug_version",
        ),
        CheckConstraint(
            "source_kind IN ('CUSTOM','CANONICAL_OVERRIDE')",
            name="ck_agent_studio_source_kind",
        ),
        CheckConstraint(
            "lifecycle_state IN ('DRAFT','REVIEW','APPROVED','ACTIVE','SUSPENDED','RETIRED')",
            name="ck_agent_studio_lifecycle_state",
        ),
        CheckConstraint(
            "temperature >= 0 AND temperature <= 2",
            name="ck_agent_studio_temperature",
        ),
        CheckConstraint(
            "daily_budget_usd IS NULL OR daily_budget_usd >= 0",
            name="ck_agent_studio_daily_budget_nonnegative",
        ),
        CheckConstraint(
            "monthly_budget_usd IS NULL OR monthly_budget_usd >= 0",
            name="ck_agent_studio_monthly_budget_nonnegative",
        ),
        Index(
            "ix_agent_studio_tenant_slug_state",
            "tenant_id",
            "agent_slug",
            "lifecycle_state",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        index=True,
    )
    agent_slug: Mapped[str] = mapped_column(String(80), index=True)
    base_agent_slug: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    source_kind: Mapped[str] = mapped_column(String(32), default="CUSTOM", index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)

    display_name: Mapped[str] = mapped_column(String(160))
    canonical_name: Mapped[str] = mapped_column(String(160))
    role_label: Mapped[str] = mapped_column(String(200), default="")
    department: Mapped[str] = mapped_column(String(160), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    system_instruction: Mapped[str] = mapped_column(Text, default="")

    provider: Mapped[str] = mapped_column(String(80), default="openai")
    model_name: Mapped[str] = mapped_column(String(160), default="")
    temperature: Mapped[Decimal] = mapped_column(Numeric(4, 2), default=Decimal("0.20"))

    capabilities_json: Mapped[dict] = mapped_column(JSON, default=dict)
    knowledge_config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    daily_budget_usd: Mapped[Decimal | None] = mapped_column(Numeric(14, 4), nullable=True)
    monthly_budget_usd: Mapped[Decimal | None] = mapped_column(Numeric(14, 4), nullable=True)

    lifecycle_state: Mapped[str] = mapped_column(String(24), default="DRAFT", index=True)
    runtime_enabled: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    review_evidence_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)
    approval_evidence_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)

    created_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    updated_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    approved_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UserExperienceProfile(Base):
    __tablename__ = "user_experience_profiles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_user_experience_profile_tenant_user"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    co_creator_name: Mapped[str] = mapped_column(String(64), default="Co-Criador")
    onboarding_goal: Mapped[str | None] = mapped_column(String(240), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, onupdate=now
    )


class AccessGrantRedemption(Base):
    __tablename__ = "access_grant_redemptions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    grant_jti: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    redeemed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class NativeAuthThrottle(Base):
    __tablename__ = "native_auth_throttles"
    __table_args__ = (UniqueConstraint("scope", "key_hash", name="uq_native_auth_throttle_scope_key"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    scope: Mapped[str] = mapped_column(String(40))
    key_hash: Mapped[str] = mapped_column(String(64))
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class NativeAuthChallenge(Base):
    __tablename__ = "native_auth_challenges"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(16), index=True)
    purpose: Mapped[str] = mapped_column(String(40), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)


class NativeMfaFactor(Base):
    __tablename__ = "native_mfa_factors"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True)
    factor_type: Mapped[str] = mapped_column(String(24), default="totp")
    encrypted_secret: Mapped[str] = mapped_column(Text)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class NativeMfaRecoveryCode(Base):
    __tablename__ = "native_mfa_recovery_codes"
    __table_args__ = (UniqueConstraint("user_id", "code_hash", name="uq_native_mfa_recovery_user_code"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    code_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
