"""Native PatroAI authentication credentials and sessions.

Revision ID: 003_native_auth
Revises: 002_hyper_cocreator
"""
from alembic import op
import sqlalchemy as sa

revision = "003_native_auth"
down_revision = "002_hyper_cocreator"
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
    if not _table_exists("native_credentials"):
        op.create_table(
            "native_credentials",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column(
                "user_id",
                sa.String(64),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
                unique=True,
            ),
            sa.Column("password_hash", sa.String(512), nullable=False),
            sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("password_updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    _ensure_index("ix_native_credentials_user_id", "native_credentials", ["user_id"], unique=True)

    if not _table_exists("native_sessions"):
        op.create_table(
            "native_sessions",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("session_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("token_prefix", sa.String(16), nullable=False),
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
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("user_agent", sa.String(240), nullable=False, server_default=""),
            sa.Column("ip_prefix", sa.String(80), nullable=False, server_default=""),
        )
    _ensure_index("ix_native_sessions_session_hash", "native_sessions", ["session_hash"], unique=True)
    _ensure_index("ix_native_sessions_token_prefix", "native_sessions", ["token_prefix"])
    _ensure_index("ix_native_sessions_tenant_id", "native_sessions", ["tenant_id"])
    _ensure_index("ix_native_sessions_user_id", "native_sessions", ["user_id"])
    _ensure_index("ix_native_sessions_expires_at", "native_sessions", ["expires_at"])

    if not _table_exists("native_password_resets"):
        op.create_table(
            "native_password_resets",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("token_prefix", sa.String(16), nullable=False),
            sa.Column(
                "user_id",
                sa.String(64),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        )
    _ensure_index("ix_native_password_resets_token_hash", "native_password_resets", ["token_hash"], unique=True)
    _ensure_index("ix_native_password_resets_token_prefix", "native_password_resets", ["token_prefix"])
    _ensure_index("ix_native_password_resets_user_id", "native_password_resets", ["user_id"])
    _ensure_index("ix_native_password_resets_expires_at", "native_password_resets", ["expires_at"])


def downgrade():
    op.drop_index("ix_native_password_resets_expires_at", table_name="native_password_resets")
    op.drop_index("ix_native_password_resets_user_id", table_name="native_password_resets")
    op.drop_index("ix_native_password_resets_token_prefix", table_name="native_password_resets")
    op.drop_index("ix_native_password_resets_token_hash", table_name="native_password_resets")
    op.drop_table("native_password_resets")
    op.drop_index("ix_native_sessions_expires_at", table_name="native_sessions")
    op.drop_index("ix_native_sessions_user_id", table_name="native_sessions")
    op.drop_index("ix_native_sessions_tenant_id", table_name="native_sessions")
    op.drop_index("ix_native_sessions_token_prefix", table_name="native_sessions")
    op.drop_index("ix_native_sessions_session_hash", table_name="native_sessions")
    op.drop_table("native_sessions")
    op.drop_index("ix_native_credentials_user_id", table_name="native_credentials")
    op.drop_table("native_credentials")
