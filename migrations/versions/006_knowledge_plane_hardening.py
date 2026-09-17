"""PatroAI Platform Knowledge Plane integrity hardening.

Revision ID: 006_knowledge_plane_hardening
Revises: 005_knowledge_plane_v1

Adds database invariants and a durable orphan-blob cleanup queue without
mutating existing thread/attachment data.
"""
from alembic import op
import sqlalchemy as sa


revision = "006_knowledge_plane_hardening"
down_revision = "005_knowledge_plane_v1"
branch_labels = None
depends_on = None


_SCOPE_CHECK = "scope IN ('PERSONAL','INSTITUTIONAL','PLATFORM')"
_STATUS_CHECK = "status IN ('DRAFT','ACTIVE','SUPERSEDED','REVOKED')"
_VERSION_CHECK = "version >= 1"
_SCOPE_TENANT_OWNER_CHECK = (
    "("
    "(scope = 'PLATFORM' AND tenant_id IS NULL AND owner_user_id IS NULL) OR "
    "(scope = 'INSTITUTIONAL' AND tenant_id IS NOT NULL AND owner_user_id IS NULL) OR "
    "(scope = 'PERSONAL' AND tenant_id IS NOT NULL AND owner_user_id IS NOT NULL)"
    ")"
)
_SQLITE_PURPOSE_CHECK = (
    "json_valid(allowed_purposes) = 1 "
    "AND json_type(allowed_purposes) = 'array' "
    "AND json_array_length(allowed_purposes) BETWEEN 1 AND 3 "
    "AND json_extract(allowed_purposes, '$[0]') IN ('chat','team','realtime') "
    "AND (json_array_length(allowed_purposes) < 2 OR "
    "     json_extract(allowed_purposes, '$[1]') IN ('chat','team','realtime')) "
    "AND (json_array_length(allowed_purposes) < 3 OR "
    "     json_extract(allowed_purposes, '$[2]') IN ('chat','team','realtime')) "
    "AND (json_array_length(allowed_purposes) < 2 OR "
    "     json_extract(allowed_purposes, '$[0]') <> json_extract(allowed_purposes, '$[1]')) "
    "AND (json_array_length(allowed_purposes) < 3 OR "
    "     (json_extract(allowed_purposes, '$[0]') <> json_extract(allowed_purposes, '$[2]') "
    "      AND json_extract(allowed_purposes, '$[1]') <> json_extract(allowed_purposes, '$[2]')))"
)
_POSTGRES_PURPOSE_CHECK = (
    "jsonb_typeof(allowed_purposes::jsonb) = 'array' "
    "AND jsonb_array_length(allowed_purposes::jsonb) BETWEEN 1 AND 3 "
    "AND allowed_purposes::jsonb <@ '[\"chat\",\"team\",\"realtime\"]'::jsonb"
)


def _inspector():
    return sa.inspect(op.get_bind())


def _dialect_name() -> str:
    return op.get_bind().dialect.name


def _table_exists(name: str) -> bool:
    return _inspector().has_table(name)


def _check_names(table_name: str) -> set[str]:
    if not _table_exists(table_name):
        return set()
    return {
        item["name"]
        for item in _inspector().get_check_constraints(table_name)
        if item.get("name")
    }


def _index_names(table_name: str) -> set[str]:
    if not _table_exists(table_name):
        return set()
    return {
        item["name"]
        for item in _inspector().get_indexes(table_name)
        if item.get("name")
    }


def _create_knowledge_checks() -> None:
    desired = (
        ("ck_knowledge_scope_valid", _SCOPE_CHECK),
        ("ck_knowledge_status_valid", _STATUS_CHECK),
        ("ck_knowledge_version_positive", _VERSION_CHECK),
        ("ck_knowledge_scope_tenant_owner", _SCOPE_TENANT_OWNER_CHECK),
    )
    existing = _check_names("knowledge_documents")
    missing = [(name, expr) for name, expr in desired if name not in existing]
    dialect = _dialect_name()

    purpose_missing = "ck_knowledge_allowed_purposes_valid" not in existing
    if not missing and (not purpose_missing or dialect not in {"sqlite", "postgresql"}):
        return

    if dialect == "sqlite":
        with op.batch_alter_table("knowledge_documents", recreate="always") as batch:
            for name, expression in missing:
                batch.create_check_constraint(name, expression)
            if purpose_missing:
                batch.create_check_constraint(
                    "ck_knowledge_allowed_purposes_valid",
                    _SQLITE_PURPOSE_CHECK,
                )
        return

    for name, expression in missing:
        op.create_check_constraint(name, "knowledge_documents", expression)
    if dialect == "postgresql" and purpose_missing:
        op.create_check_constraint(
            "ck_knowledge_allowed_purposes_valid",
            "knowledge_documents",
            _POSTGRES_PURPOSE_CHECK,
        )


def _drop_knowledge_checks() -> None:
    existing = _check_names("knowledge_documents")
    names = [
        "ck_knowledge_scope_valid",
        "ck_knowledge_status_valid",
        "ck_knowledge_version_positive",
        "ck_knowledge_scope_tenant_owner",
        "ck_knowledge_allowed_purposes_valid",
    ]
    present = [name for name in names if name in existing]
    if not present:
        return
    dialect = _dialect_name()
    if dialect == "sqlite":
        with op.batch_alter_table("knowledge_documents", recreate="always") as batch:
            for name in reversed(present):
                batch.drop_constraint(name, type_="check")
        return
    for name in reversed(present):
        op.drop_constraint(name, "knowledge_documents", type_="check")


def _ensure_cleanup_indexes() -> None:
    for name, columns in (
        ("ix_knowledge_storage_cleanup_tenant_id", ["tenant_id"]),
        ("ix_knowledge_storage_cleanup_knowledge_id", ["knowledge_id"]),
        ("ix_knowledge_storage_cleanup_status", ["status"]),
    ):
        if name not in _index_names("knowledge_storage_cleanup"):
            op.create_index(name, "knowledge_storage_cleanup", columns)


def upgrade() -> None:
    _create_knowledge_checks()

    if not _table_exists("knowledge_storage_cleanup"):
        op.create_table(
            "knowledge_storage_cleanup",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("tenant_id", sa.String(64), nullable=True),
            sa.Column("knowledge_id", sa.String(64), nullable=True),
            sa.Column("storage_key", sa.String(500), nullable=False),
            sa.Column("reason", sa.String(80), nullable=False),
            sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_error", sa.String(160), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "storage_key",
                name="uq_knowledge_storage_cleanup_key",
            ),
            sa.CheckConstraint(
                "status IN ('PENDING','DONE')",
                name="ck_knowledge_storage_cleanup_status",
            ),
            sa.CheckConstraint(
                "attempts >= 0",
                name="ck_knowledge_storage_cleanup_attempts",
            ),
        )
    _ensure_cleanup_indexes()


def downgrade() -> None:
    if _table_exists("knowledge_storage_cleanup"):
        op.drop_table("knowledge_storage_cleanup")
    _drop_knowledge_checks()
