"""Hyper Co-Creator onboarding profile and one-time access grant redemption.

Revision ID: 002_hyper_cocreator
Revises: 001_v2_foundation
"""
from alembic import op
import sqlalchemy as sa

revision = "002_hyper_cocreator"
down_revision = "001_v2_foundation"
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


def upgrade():
    if not _table_exists("user_experience_profiles"):
        op.create_table(
            "user_experience_profiles",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(64),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "user_id",
                sa.String(64),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("co_creator_name", sa.String(64), nullable=False, server_default="Co-Criador"),
            sa.Column("onboarding_goal", sa.String(240), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "tenant_id",
                "user_id",
                name="uq_user_experience_profile_tenant_user",
            ),
        )
    _ensure_index(
        "ix_user_experience_profiles_tenant_id",
        "user_experience_profiles",
        ["tenant_id"],
    )
    _ensure_index(
        "ix_user_experience_profiles_user_id",
        "user_experience_profiles",
        ["user_id"],
    )

    if not _table_exists("access_grant_redemptions"):
        op.create_table(
            "access_grant_redemptions",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("grant_jti", sa.String(64), nullable=False, unique=True),
            sa.Column(
                "tenant_id",
                sa.String(64),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "user_id",
                sa.String(64),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("redeemed_at", sa.DateTime(timezone=True), nullable=False),
        )
    _ensure_index(
        "ix_access_grant_redemptions_grant_jti",
        "access_grant_redemptions",
        ["grant_jti"],
        unique=True,
    )
    _ensure_index(
        "ix_access_grant_redemptions_tenant_id",
        "access_grant_redemptions",
        ["tenant_id"],
    )
    _ensure_index(
        "ix_access_grant_redemptions_user_id",
        "access_grant_redemptions",
        ["user_id"],
    )


def downgrade():
    op.drop_index(
        "ix_access_grant_redemptions_user_id",
        table_name="access_grant_redemptions",
    )
    op.drop_index(
        "ix_access_grant_redemptions_tenant_id",
        table_name="access_grant_redemptions",
    )
    op.drop_index(
        "ix_access_grant_redemptions_grant_jti",
        table_name="access_grant_redemptions",
    )
    op.drop_table("access_grant_redemptions")

    op.drop_index(
        "ix_user_experience_profiles_user_id",
        table_name="user_experience_profiles",
    )
    op.drop_index(
        "ix_user_experience_profiles_tenant_id",
        table_name="user_experience_profiles",
    )
    op.drop_table("user_experience_profiles")
