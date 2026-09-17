"""Persistent append-only capability audit evidence ledger.

Revision ID: 009_audit_evidence_ledger
Revises: 008_admin_voice_catalog

Fresh bootstraps may materialize current ORM metadata in revision 001, therefore
this migration is defensive and supports both an already-present table and an
incremental database where the table is absent.
"""
from alembic import op
import sqlalchemy as sa


revision = "009_audit_evidence_ledger"
down_revision = "008_admin_voice_catalog"
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
    columns: list[str],
    *,
    unique: bool = False,
) -> None:
    if name not in _index_names("audit_evidence_records"):
        op.create_index(
            name,
            "audit_evidence_records",
            columns,
            unique=unique,
        )


def _install_postgresql_immutability_trigger() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE OR REPLACE FUNCTION reject_audit_evidence_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'AUDIT_EVIDENCE_IMMUTABLE'
                USING ERRCODE = '55000';
        END;
        $$;
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS trg_audit_evidence_immutable
        ON audit_evidence_records;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_evidence_immutable
        BEFORE UPDATE OR DELETE ON audit_evidence_records
        FOR EACH ROW
        EXECUTE FUNCTION reject_audit_evidence_mutation();
        """
    )


def upgrade() -> None:
    if not _table_exists("audit_evidence_records"):
        op.create_table(
            "audit_evidence_records",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("schema_version", sa.String(16), nullable=False),
            sa.Column("audit_execution_id", sa.String(64), nullable=False),
            sa.Column("tenant_id", sa.String(64), nullable=False),
            sa.Column("user_id", sa.String(64), nullable=False),
            sa.Column("request_id", sa.String(64), nullable=False),
            sa.Column("execution_id", sa.String(64), nullable=False),
            sa.Column("capability_id", sa.String(120), nullable=False),
            sa.Column("capability_version", sa.String(40), nullable=False),
            sa.Column("environment", sa.String(40), nullable=False),
            sa.Column("deployment_id", sa.String(120), nullable=False),
            sa.Column("resolved_agent_id", sa.String(120), nullable=False),
            sa.Column("capability_decision", sa.String(16), nullable=False),
            sa.Column("status", sa.String(16), nullable=False),
            sa.Column("artifact_id", sa.String(64), nullable=True),
            sa.Column("root_id", sa.String(64), nullable=True),
            sa.Column("error_code", sa.String(120), nullable=True),
            sa.Column("envelope_json", sa.JSON(), nullable=False),
            sa.Column("evidence_sha256", sa.String(64), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.UniqueConstraint(
                "audit_execution_id",
                name="uq_audit_evidence_audit_execution_id",
            ),
            sa.CheckConstraint(
                "capability_decision IN ('ALLOW','DENY')",
                name="ck_audit_evidence_capability_decision",
            ),
            sa.CheckConstraint(
                "status IN ('completed','failed','denied')",
                name="ck_audit_evidence_status",
            ),
            sa.CheckConstraint(
                "length(evidence_sha256) = 64",
                name="ck_audit_evidence_sha256_length",
            ),
        )

    for name, columns in (
        ("ix_audit_evidence_records_tenant_id", ["tenant_id"]),
        ("ix_audit_evidence_records_request_id", ["request_id"]),
        ("ix_audit_evidence_records_execution_id", ["execution_id"]),
        ("ix_audit_evidence_records_capability_id", ["capability_id"]),
        ("ix_audit_evidence_records_resolved_agent_id", ["resolved_agent_id"]),
        ("ix_audit_evidence_tenant_created", ["tenant_id", "created_at"]),
        (
            "ix_audit_evidence_tenant_execution_created",
            ["tenant_id", "execution_id", "created_at"],
        ),
        (
            "ix_audit_evidence_tenant_capability_created",
            ["tenant_id", "capability_id", "created_at"],
        ),
    ):
        _ensure_index(name, columns)

    _install_postgresql_immutability_trigger()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and _table_exists("audit_evidence_records"):
        op.execute(
            """
            DROP TRIGGER IF EXISTS trg_audit_evidence_immutable
            ON audit_evidence_records;
            """
        )
        op.execute(
            "DROP FUNCTION IF EXISTS reject_audit_evidence_mutation();"
        )
    if _table_exists("audit_evidence_records"):
        op.drop_table("audit_evidence_records")
