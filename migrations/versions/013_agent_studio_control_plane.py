"""Agent Studio control plane.

Revision ID: 013_agent_studio_control_plane
Revises: 012_platform_user_invitations

Proposal-only migration for the tenant-scoped, versioned Agent Studio control
plane. It is strictly additive and does not mutate the canonical runtime agent
catalog. Runtime activation remains fail-closed until a later, separately
governed tenant-aware runtime gate.

MUST NOT be executed without migration preflight, rollback review and explicit
human approval.
"""
from alembic import op
import sqlalchemy as sa

revision = "013_agent_studio_control_plane"
down_revision = "012_platform_user_invitations"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _table_exists(name: str) -> bool:
    return _inspector().has_table(name)


def upgrade() -> None:
    if _table_exists("agent_studio_versions"):
        return

    op.create_table(
        "agent_studio_versions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("agent_slug", sa.String(80), nullable=False),
        sa.Column("base_agent_slug", sa.String(80), nullable=True),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("display_name", sa.String(160), nullable=False),
        sa.Column("canonical_name", sa.String(160), nullable=False),
        sa.Column("role_label", sa.String(200), nullable=False),
        sa.Column("department", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("system_instruction", sa.Text(), nullable=False),
        sa.Column("provider", sa.String(80), nullable=False),
        sa.Column("model_name", sa.String(160), nullable=False),
        sa.Column("temperature", sa.Numeric(4, 2), nullable=False),
        sa.Column("capabilities_json", sa.JSON(), nullable=False),
        sa.Column("knowledge_config_json", sa.JSON(), nullable=False),
        sa.Column("daily_budget_usd", sa.Numeric(14, 4), nullable=True),
        sa.Column("monthly_budget_usd", sa.Numeric(14, 4), nullable=True),
        sa.Column("lifecycle_state", sa.String(24), nullable=False),
        sa.Column("runtime_enabled", sa.Boolean(), nullable=False),
        sa.Column("review_evidence_ref", sa.String(500), nullable=True),
        sa.Column("approval_evidence_ref", sa.String(500), nullable=True),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("updated_by", sa.String(64), nullable=False),
        sa.Column("approved_by", sa.String(64), nullable=True),
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
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint(
            "tenant_id",
            "agent_slug",
            "version",
            name="uq_agent_studio_tenant_slug_version",
        ),
        sa.CheckConstraint(
            "source_kind IN ('CUSTOM','CANONICAL_OVERRIDE')",
            name="ck_agent_studio_source_kind",
        ),
        sa.CheckConstraint(
            "lifecycle_state IN ('DRAFT','REVIEW','APPROVED','ACTIVE','SUSPENDED','RETIRED')",
            name="ck_agent_studio_lifecycle_state",
        ),
        sa.CheckConstraint(
            "temperature >= 0 AND temperature <= 2",
            name="ck_agent_studio_temperature",
        ),
        sa.CheckConstraint(
            "daily_budget_usd IS NULL OR daily_budget_usd >= 0",
            name="ck_agent_studio_daily_budget_nonnegative",
        ),
        sa.CheckConstraint(
            "monthly_budget_usd IS NULL OR monthly_budget_usd >= 0",
            name="ck_agent_studio_monthly_budget_nonnegative",
        ),
    )

    for name, columns in (
        ("ix_agent_studio_versions_tenant_id", ["tenant_id"]),
        ("ix_agent_studio_versions_agent_slug", ["agent_slug"]),
        ("ix_agent_studio_versions_base_agent_slug", ["base_agent_slug"]),
        ("ix_agent_studio_versions_source_kind", ["source_kind"]),
        ("ix_agent_studio_versions_lifecycle_state", ["lifecycle_state"]),
        ("ix_agent_studio_versions_runtime_enabled", ["runtime_enabled"]),
        ("ix_agent_studio_versions_created_by", ["created_by"]),
        ("ix_agent_studio_versions_updated_by", ["updated_by"]),
        ("ix_agent_studio_versions_approved_by", ["approved_by"]),
    ):
        op.create_index(name, "agent_studio_versions", columns, unique=False)

    op.create_index(
        "ix_agent_studio_tenant_slug_state",
        "agent_studio_versions",
        ["tenant_id", "agent_slug", "lifecycle_state"],
        unique=False,
    )


def downgrade() -> None:
    if _table_exists("agent_studio_versions"):
        op.drop_table("agent_studio_versions")
