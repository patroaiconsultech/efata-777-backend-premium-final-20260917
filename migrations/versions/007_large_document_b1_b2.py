"""PatroAI Platform large-document canonicalization + navigator.

Revision ID: 007_large_document_b1_b2
Revises: 006_knowledge_plane_hardening

Additive migration only. Existing knowledge rows and attachment data are untouched.
"""
from alembic import op
import sqlalchemy as sa

revision = "007_large_document_b1_b2"
down_revision = "006_knowledge_plane_hardening"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _table_exists(name: str) -> bool:
    return _inspector().has_table(name)


def _index_names(table_name: str) -> set[str]:
    if not _table_exists(table_name):
        return set()
    return {
        item["name"]
        for item in _inspector().get_indexes(table_name)
        if item.get("name")
    }


def _ensure_index(table: str, name: str, columns: list[str]) -> None:
    if name not in _index_names(table):
        op.create_index(name, table, columns)


def upgrade() -> None:
    if not _table_exists("knowledge_document_derivatives"):
        op.create_table(
            "knowledge_document_derivatives",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("knowledge_id", sa.String(64), nullable=False),
            sa.Column("tenant_id", sa.String(64), nullable=True),
            sa.Column("kind", sa.String(40), nullable=False, server_default="CANONICAL_MARKDOWN"),
            sa.Column("storage_key", sa.String(500), nullable=True),
            sa.Column("sha256", sa.String(64), nullable=True),
            sa.Column("size_bytes", sa.Integer(), nullable=True),
            sa.Column("status", sa.String(24), nullable=False, server_default="PENDING"),
            sa.Column("extractor", sa.String(80), nullable=True),
            sa.Column("extractor_version", sa.String(40), nullable=True),
            sa.Column("source_chars", sa.Integer(), nullable=True),
            sa.Column("canonical_chars", sa.Integer(), nullable=True),
            sa.Column("page_count", sa.Integer(), nullable=True),
            sa.Column("warnings_json", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["knowledge_id"], ["knowledge_documents.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("knowledge_id", "kind", name="uq_knowledge_derivative_kind"),
            sa.UniqueConstraint("storage_key", name="uq_knowledge_derivative_storage_key"),
            sa.CheckConstraint(
                "status IN ('PENDING','PROCESSING','READY','PARTIAL','FAILED','OCR_REQUIRED')",
                name="ck_knowledge_derivative_status",
            ),
        )
    for name, cols in (
        ("ix_knowledge_derivatives_knowledge_id", ["knowledge_id"]),
        ("ix_knowledge_derivatives_tenant_id", ["tenant_id"]),
        ("ix_knowledge_derivatives_status", ["status"]),
    ):
        _ensure_index("knowledge_document_derivatives", name, cols)

    if not _table_exists("knowledge_document_sections"):
        op.create_table(
            "knowledge_document_sections",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("knowledge_id", sa.String(64), nullable=False),
            sa.Column("derivative_id", sa.String(64), nullable=False),
            sa.Column("tenant_id", sa.String(64), nullable=True),
            sa.Column("parent_section_id", sa.String(64), nullable=True),
            sa.Column("ordinal", sa.Integer(), nullable=False),
            sa.Column("heading", sa.String(500), nullable=False),
            sa.Column("level", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("page_start", sa.Integer(), nullable=True),
            sa.Column("page_end", sa.Integer(), nullable=True),
            sa.Column("byte_start", sa.Integer(), nullable=False),
            sa.Column("byte_end", sa.Integer(), nullable=False),
            sa.Column("estimated_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["knowledge_id"], ["knowledge_documents.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["derivative_id"], ["knowledge_document_derivatives.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["parent_section_id"], ["knowledge_document_sections.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("knowledge_id", "ordinal", name="uq_knowledge_section_ordinal"),
            sa.CheckConstraint("level >= 0", name="ck_knowledge_section_level_nonnegative"),
            sa.CheckConstraint("byte_end >= byte_start", name="ck_knowledge_section_byte_range"),
        )
    for name, cols in (
        ("ix_knowledge_sections_knowledge_id", ["knowledge_id"]),
        ("ix_knowledge_sections_derivative_id", ["derivative_id"]),
        ("ix_knowledge_sections_tenant_id", ["tenant_id"]),
        ("ix_knowledge_sections_parent_id", ["parent_section_id"]),
    ):
        _ensure_index("knowledge_document_sections", name, cols)

    if not _table_exists("knowledge_document_chunks"):
        op.create_table(
            "knowledge_document_chunks",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("knowledge_id", sa.String(64), nullable=False),
            sa.Column("derivative_id", sa.String(64), nullable=False),
            sa.Column("section_id", sa.String(64), nullable=True),
            sa.Column("tenant_id", sa.String(64), nullable=True),
            sa.Column("ordinal", sa.Integer(), nullable=False),
            sa.Column("byte_start", sa.Integer(), nullable=False),
            sa.Column("byte_end", sa.Integer(), nullable=False),
            sa.Column("estimated_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("text_sha256", sa.String(64), nullable=False),
            sa.Column("terms_json", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["knowledge_id"], ["knowledge_documents.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["derivative_id"], ["knowledge_document_derivatives.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["section_id"], ["knowledge_document_sections.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("knowledge_id", "ordinal", name="uq_knowledge_chunk_ordinal"),
            sa.CheckConstraint("byte_end > byte_start", name="ck_knowledge_chunk_byte_range"),
        )
    for name, cols in (
        ("ix_knowledge_chunks_knowledge_id", ["knowledge_id"]),
        ("ix_knowledge_chunks_derivative_id", ["derivative_id"]),
        ("ix_knowledge_chunks_section_id", ["section_id"]),
        ("ix_knowledge_chunks_tenant_id", ["tenant_id"]),
    ):
        _ensure_index("knowledge_document_chunks", name, cols)

    if not _table_exists("knowledge_document_selections"):
        op.create_table(
            "knowledge_document_selections",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("knowledge_id", sa.String(64), nullable=False),
            sa.Column("tenant_id", sa.String(64), nullable=False),
            sa.Column("user_id", sa.String(64), nullable=False),
            sa.Column("mode", sa.String(16), nullable=False, server_default="AUTO"),
            sa.Column("section_ids", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["knowledge_id"], ["knowledge_documents.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.UniqueConstraint(
                "knowledge_id", "tenant_id", "user_id",
                name="uq_knowledge_selection_actor_document",
            ),
            sa.CheckConstraint("mode IN ('MANUAL','AUTO')", name="ck_knowledge_selection_mode"),
        )
    for name, cols in (
        ("ix_knowledge_selections_knowledge_id", ["knowledge_id"]),
        ("ix_knowledge_selections_tenant_id", ["tenant_id"]),
        ("ix_knowledge_selections_user_id", ["user_id"]),
    ):
        _ensure_index("knowledge_document_selections", name, cols)


def downgrade() -> None:
    for table in (
        "knowledge_document_selections",
        "knowledge_document_chunks",
        "knowledge_document_sections",
        "knowledge_document_derivatives",
    ):
        if _table_exists(table):
            op.drop_table(table)
