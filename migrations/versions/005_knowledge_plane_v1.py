"""PatroAI Platform governed Knowledge Plane.

Revision ID: 005_knowledge_plane_v1
Revises: 004_rc1_auth_d

Additive only: introduces governed knowledge metadata/versioning without
mutating existing attachment/thread data.
"""
from alembic import op
import sqlalchemy as sa

revision = "005_knowledge_plane_v1"
down_revision = "004_rc1_auth_d"
branch_labels = None
depends_on = None


def _table_exists(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _index_names(table_name: str) -> set[str]:
    return {
        item["name"]
        for item in sa.inspect(op.get_bind()).get_indexes(table_name)
        if item.get("name")
    }


def _ensure_index(name: str, table_name: str, columns: list[str], *, unique: bool = False) -> None:
    if name not in _index_names(table_name):
        op.create_index(name, table_name, columns, unique=unique)


def upgrade() -> None:
    if not _table_exists("knowledge_documents"):
        op.create_table(
            "knowledge_documents",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(64),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column(
                "owner_user_id",
                sa.String(64),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column("scope", sa.String(24), nullable=False),
            sa.Column("agent_id", sa.String(80), nullable=True),
            sa.Column("title", sa.String(240), nullable=False),
            sa.Column("source_filename", sa.String(255), nullable=False),
            sa.Column("mime_type", sa.String(120), nullable=False),
            sa.Column("size_bytes", sa.Integer(), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("storage_key", sa.String(500), nullable=False, unique=True),
            sa.Column("classification", sa.String(40), nullable=False, server_default="internal"),
            sa.Column(
                "allowed_purposes",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[\"chat\",\"team\",\"realtime\"]'"),
            ),
            sa.Column("logical_document_id", sa.String(64), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("effective_from", sa.DateTime(timezone=True), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "created_by",
                sa.String(64),
                sa.ForeignKey("users.id", ondelete="RESTRICT"),
                nullable=False,
            ),
            sa.Column(
                "approved_by",
                sa.String(64),
                sa.ForeignKey("users.id", ondelete="RESTRICT"),
                nullable=True,
            ),
            sa.Column(
                "supersedes_id",
                sa.String(64),
                sa.ForeignKey("knowledge_documents.id", ondelete="RESTRICT"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "logical_document_id",
                "version",
                name="uq_knowledge_document_logical_version",
            ),
        )

    for name, columns in (
        ("ix_knowledge_documents_tenant_id", ["tenant_id"]),
        ("ix_knowledge_documents_owner_user_id", ["owner_user_id"]),
        ("ix_knowledge_documents_scope", ["scope"]),
        ("ix_knowledge_documents_agent_id", ["agent_id"]),
        ("ix_knowledge_documents_logical_document_id", ["logical_document_id"]),
        ("ix_knowledge_documents_status", ["status"]),
        ("ix_knowledge_documents_effective_from", ["effective_from"]),
        ("ix_knowledge_documents_expires_at", ["expires_at"]),
        ("ix_knowledge_documents_created_by", ["created_by"]),
        ("ix_knowledge_documents_supersedes_id", ["supersedes_id"]),
    ):
        _ensure_index(name, "knowledge_documents", columns)


def downgrade() -> None:
    if _table_exists("knowledge_documents"):
        # Additive staging rollback only. Production rollback after real user
        # knowledge exists must keep this table inert rather than delete data.
        op.drop_table("knowledge_documents")
