"""RC1-AUTH-D cumulative native authentication hardening.

Revision ID: 004_rc1_auth_d
Revises: 003_native_auth

Adds only reversible authentication metadata/tables. No tenant or business data is moved.
"""
from alembic import op
import sqlalchemy as sa

revision = "004_rc1_auth_d"
down_revision = "003_native_auth"
branch_labels = None
depends_on = None


def _table_exists(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _column_names(table_name: str) -> set[str]:
    return {
        item["name"]
        for item in sa.inspect(op.get_bind()).get_columns(table_name)
    }


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
    if "email_verified_at" not in _column_names("users"):
        op.add_column(
            "users",
            sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        )

    session_columns = _column_names("native_sessions")
    if "previous_session_hash" not in session_columns:
        op.add_column(
            "native_sessions",
            sa.Column("previous_session_hash", sa.String(64), nullable=True),
        )
    if "rotation_grace_expires_at" not in _column_names("native_sessions"):
        op.add_column(
            "native_sessions",
            sa.Column("rotation_grace_expires_at", sa.DateTime(timezone=True), nullable=True),
        )
    _ensure_index(
        "ix_native_sessions_previous_session_hash",
        "native_sessions",
        ["previous_session_hash"],
    )
    if "last_rotated_at" not in _column_names("native_sessions"):
        op.add_column(
            "native_sessions",
            sa.Column("last_rotated_at", sa.DateTime(timezone=True), nullable=True),
        )
    if "authenticated_at" not in _column_names("native_sessions"):
        op.add_column(
            "native_sessions",
            sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=True),
        )
    if "mfa_verified_at" not in _column_names("native_sessions"):
        op.add_column(
            "native_sessions",
            sa.Column("mfa_verified_at", sa.DateTime(timezone=True), nullable=True),
        )
    if "reauthenticated_at" not in _column_names("native_sessions"):
        op.add_column(
            "native_sessions",
            sa.Column("reauthenticated_at", sa.DateTime(timezone=True), nullable=True),
        )
    op.execute(
        "UPDATE native_sessions "
        "SET last_rotated_at = created_at, authenticated_at = created_at "
        "WHERE last_rotated_at IS NULL OR authenticated_at IS NULL"
    )

    if not _table_exists("native_auth_throttles"):
        op.create_table(
            "native_auth_throttles",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("scope", sa.String(40), nullable=False),
            sa.Column("key_hash", sa.String(64), nullable=False),
            sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "scope", "key_hash", name="uq_native_auth_throttle_scope_key"
            ),
        )
    _ensure_index("ix_native_auth_throttles_scope", "native_auth_throttles", ["scope"])
    _ensure_index("ix_native_auth_throttles_key_hash", "native_auth_throttles", ["key_hash"])

    if not _table_exists("native_auth_challenges"):
        op.create_table(
            "native_auth_challenges",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("token_prefix", sa.String(16), nullable=False),
            sa.Column("purpose", sa.String(40), nullable=False),
            sa.Column(
                "user_id",
                sa.String(64),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "tenant_id",
                sa.String(64),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        )
    _ensure_index(
        "ix_native_auth_challenges_token_hash",
        "native_auth_challenges",
        ["token_hash"],
        unique=True,
    )
    _ensure_index("ix_native_auth_challenges_token_prefix", "native_auth_challenges", ["token_prefix"])
    _ensure_index("ix_native_auth_challenges_purpose", "native_auth_challenges", ["purpose"])
    _ensure_index("ix_native_auth_challenges_user_id", "native_auth_challenges", ["user_id"])
    _ensure_index("ix_native_auth_challenges_tenant_id", "native_auth_challenges", ["tenant_id"])
    _ensure_index("ix_native_auth_challenges_expires_at", "native_auth_challenges", ["expires_at"])

    if not _table_exists("native_mfa_factors"):
        op.create_table(
            "native_mfa_factors",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column(
                "user_id",
                sa.String(64),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
                unique=True,
            ),
            sa.Column("factor_type", sa.String(24), nullable=False, server_default="totp"),
            sa.Column("encrypted_secret", sa.Text(), nullable=False),
            sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_used_step", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    _ensure_index("ix_native_mfa_factors_user_id", "native_mfa_factors", ["user_id"], unique=True)

    if not _table_exists("native_mfa_recovery_codes"):
        op.create_table(
            "native_mfa_recovery_codes",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column(
                "user_id",
                sa.String(64),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("code_hash", sa.String(64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint(
                "user_id", "code_hash", name="uq_native_mfa_recovery_user_code"
            ),
        )
    _ensure_index("ix_native_mfa_recovery_codes_user_id", "native_mfa_recovery_codes", ["user_id"])
    _ensure_index("ix_native_mfa_recovery_codes_code_hash", "native_mfa_recovery_codes", ["code_hash"])


def downgrade():
    op.drop_index(
        "ix_native_mfa_recovery_codes_code_hash",
        table_name="native_mfa_recovery_codes",
    )
    op.drop_index(
        "ix_native_mfa_recovery_codes_user_id",
        table_name="native_mfa_recovery_codes",
    )
    op.drop_table("native_mfa_recovery_codes")

    op.drop_index("ix_native_mfa_factors_user_id", table_name="native_mfa_factors")
    op.drop_table("native_mfa_factors")

    op.drop_index(
        "ix_native_auth_challenges_expires_at",
        table_name="native_auth_challenges",
    )
    op.drop_index(
        "ix_native_auth_challenges_tenant_id",
        table_name="native_auth_challenges",
    )
    op.drop_index(
        "ix_native_auth_challenges_user_id",
        table_name="native_auth_challenges",
    )
    op.drop_index(
        "ix_native_auth_challenges_purpose",
        table_name="native_auth_challenges",
    )
    op.drop_index(
        "ix_native_auth_challenges_token_prefix",
        table_name="native_auth_challenges",
    )
    op.drop_index(
        "ix_native_auth_challenges_token_hash",
        table_name="native_auth_challenges",
    )
    op.drop_table("native_auth_challenges")

    op.drop_index(
        "ix_native_auth_throttles_key_hash",
        table_name="native_auth_throttles",
    )
    op.drop_index(
        "ix_native_auth_throttles_scope",
        table_name="native_auth_throttles",
    )
    op.drop_table("native_auth_throttles")

    op.drop_column("native_sessions", "reauthenticated_at")
    op.drop_column("native_sessions", "mfa_verified_at")
    op.drop_column("native_sessions", "authenticated_at")
    op.drop_column("native_sessions", "last_rotated_at")
    op.drop_index(
        "ix_native_sessions_previous_session_hash",
        table_name="native_sessions",
    )
    op.drop_column("native_sessions", "rotation_grace_expires_at")
    op.drop_column("native_sessions", "previous_session_hash")
    op.drop_column("users", "email_verified_at")
