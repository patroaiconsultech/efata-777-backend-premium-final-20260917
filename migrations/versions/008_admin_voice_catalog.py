"""Admin voice catalog.

Revision ID: 008_admin_voice_catalog
Revises: 007_large_document_b1_b2

The V2 foundation migration historically imports the current ORM metadata and may
therefore materialize these tables early during a fresh bootstrap. This migration
must support both legitimate states:
- the voice tables already exist because 001 created current metadata; or
- the voice tables are absent on an incrementally upgraded database.

No existing table is dropped or recreated during upgrade.
"""
from alembic import op
import sqlalchemy as sa

revision = "008_admin_voice_catalog"
down_revision = "007_large_document_b1_b2"
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


def _ensure_index(
    name: str,
    table_name: str,
    columns: list[str],
    *,
    unique: bool = False,
    postgresql_where=None,
) -> None:
    if name in _index_names(table_name):
        return
    kwargs = {"unique": unique}
    if postgresql_where is not None:
        kwargs["postgresql_where"] = postgresql_where
    op.create_index(name, table_name, columns, **kwargs)


def upgrade() -> None:
    if not _table_exists("voice_catalog_entries"):
        op.create_table(
            "voice_catalog_entries",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("provider_key", sa.String(80), nullable=False),
            sa.Column("provider_voice_id", sa.String(120), nullable=False),
            sa.Column("display_name", sa.String(120), nullable=False),
            sa.Column("provider_model", sa.String(120), nullable=False),
            sa.Column("source_type", sa.String(32), nullable=False),
            sa.Column("license_label", sa.String(160), nullable=False),
            sa.Column("cost_class", sa.String(40), nullable=False),
            sa.Column("provenance_url", sa.String(500)),
            sa.Column("catalog_version", sa.String(64), nullable=False),
            sa.Column("supported_locales", sa.JSON(), nullable=False),
            sa.Column("delivery_modes", sa.JSON(), nullable=False),
            sa.Column("curation_status", sa.String(32), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.UniqueConstraint(
                "provider_key",
                "provider_voice_id",
                name="uq_voice_catalog_provider_voice",
            ),
        )

    for name, columns in (
        ("ix_voice_catalog_entries_provider_key", ["provider_key"]),
        ("ix_voice_catalog_entries_curation_status", ["curation_status"]),
        ("ix_voice_catalog_entries_active", ["active"]),
    ):
        _ensure_index(name, "voice_catalog_entries", columns)

    if not _table_exists("agent_voice_assignments"):
        op.create_table(
            "agent_voice_assignments",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("tenant_id", sa.String(64), nullable=False),
            sa.Column("agent_slug", sa.String(80), nullable=False),
            sa.Column("voice_catalog_id", sa.String(64), nullable=False),
            sa.Column("locale", sa.String(24), nullable=False),
            sa.Column("delivery_modes", sa.JSON(), nullable=False),
            sa.Column("presentation_label", sa.String(24), nullable=False),
            sa.Column("timbre_label", sa.String(80)),
            sa.Column("energy_label", sa.String(80)),
            sa.Column("assignment_state", sa.String(24), nullable=False),
            sa.Column("validation_status", sa.String(24), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("created_by", sa.String(64), nullable=False),
            sa.Column("updated_by", sa.String(64), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(
                ["voice_catalog_id"],
                ["voice_catalog_entries.id"],
                ondelete="RESTRICT",
            ),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["updated_by"], ["users.id"], ondelete="RESTRICT"),
            sa.CheckConstraint(
                "assignment_state IN ('DRAFT','ACTIVE','DISABLED')",
                name="ck_agent_voice_assignment_state",
            ),
            sa.CheckConstraint(
                "validation_status IN ('UNVALIDATED','VALIDATED','FAILED')",
                name="ck_agent_voice_validation_status",
            ),
            sa.CheckConstraint(
                "NOT (assignment_state = 'ACTIVE' AND validation_status != 'VALIDATED')",
                name="ck_agent_voice_active_requires_validated",
            ),
        )

    for name, columns in (
        ("ix_agent_voice_assignments_tenant_id", ["tenant_id"]),
        ("ix_agent_voice_assignments_agent_slug", ["agent_slug"]),
        ("ix_agent_voice_assignments_voice_catalog_id", ["voice_catalog_id"]),
        ("ix_agent_voice_assignments_assignment_state", ["assignment_state"]),
        ("ix_agent_voice_assignments_validation_status", ["validation_status"]),
        ("ix_agent_voice_assignments_active", ["active"]),
        ("ix_agent_voice_assignments_created_by", ["created_by"]),
        ("ix_agent_voice_assignments_updated_by", ["updated_by"]),
    ):
        _ensure_index(name, "agent_voice_assignments", columns)

    _ensure_index(
        "uq_agent_voice_assignment_active",
        "agent_voice_assignments",
        ["tenant_id", "agent_slug", "locale"],
        unique=True,
        postgresql_where=sa.text("active"),
    )
    _ensure_index(
        "uq_agent_voice_unique_active",
        "agent_voice_assignments",
        ["tenant_id", "voice_catalog_id"],
        unique=True,
        postgresql_where=sa.text("active"),
    )


def downgrade() -> None:
    if _table_exists("agent_voice_assignments"):
        op.drop_table("agent_voice_assignments")
    if _table_exists("voice_catalog_entries"):
        op.drop_table("voice_catalog_entries")
