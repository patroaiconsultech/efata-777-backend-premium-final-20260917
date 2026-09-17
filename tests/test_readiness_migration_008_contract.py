from __future__ import annotations

from sqlalchemy import text

from conftest import engine
from orkio_v2.models import VoiceCatalogEntry


EXPECTED_HEAD = "012_platform_user_invitations"
LEGACY_HEAD = "007_large_document_b1_b2"


def _set_head(revision: str) -> None:
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE alembic_version SET version_num=:revision"),
            {"revision": revision},
        )


def test_health_is_liveness_when_voice_schema_is_incomplete(client):
    VoiceCatalogEntry.__table__.drop(engine)
    try:
        health = client.get("/api/v2/health")
        ready = client.get("/api/v2/ready")

        assert health.status_code == 200
        assert ready.status_code == 503
        assert "voice_catalog_entries" in ready.json()["detail"]["checks"]["missing_tables"]
    finally:
        VoiceCatalogEntry.__table__.create(engine)


def test_ready_accepts_complete_schema_at_head_008(client):
    _set_head(EXPECTED_HEAD)
    response = client.get("/api/v2/ready")

    assert response.status_code == 200
    assert response.json()["checks"]["migration_head"] == EXPECTED_HEAD
    assert response.json()["checks"]["migration_expected"] == EXPECTED_HEAD
    assert response.json()["checks"]["migration_current"] is True


def test_ready_rejects_legacy_head_007(client):
    _set_head(LEGACY_HEAD)
    try:
        response = client.get("/api/v2/ready")

        assert response.status_code == 503
        assert response.json()["detail"]["checks"]["migration_head"] == LEGACY_HEAD
        assert response.json()["detail"]["checks"]["migration_expected"] == EXPECTED_HEAD
        assert response.json()["detail"]["checks"]["migration_current"] is False
    finally:
        _set_head(EXPECTED_HEAD)


def test_ready_rejects_unknown_head_fail_closed(client):
    _set_head("unknown_revision")
    try:
        response = client.get("/api/v2/ready")

        assert response.status_code == 503
        assert response.json()["detail"]["checks"]["migration_current"] is False
    finally:
        _set_head(EXPECTED_HEAD)
