"""Testes da fundação funcional: readiness, listagem, papéis, LLM e SSE.

Cobrem os requisitos da Fase 8 aplicáveis ao backend, incluindo os casos
negativos que garantem fail-closed.
"""

import json

import pytest
from conftest import Testing, headers

from orkio_v2.config import get_settings
from orkio_v2.models import Membership, Thread, ThreadParticipant, User


# --------------------------------------------------------------------------
# Readiness
# --------------------------------------------------------------------------

def test_health_does_not_prove_database(client):
    """O liveness permanece estático e não deve ser confundido com readiness."""
    body = client.get("/api/v2/health").json()
    assert body["status"] == "ok"
    assert "checks" not in body


def test_ready_reports_schema_and_driver(client):
    response = client.get("/api/v2/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"]["database_connect"] is True
    assert body["checks"]["schema_complete"] is True
    assert body["checks"]["driver"] == "sqlite"


def test_ready_does_not_expose_credentials(client):
    raw = client.get("/api/v2/ready").text.lower()
    for leak in ("password", "@", "sqlalchemy.url", "database_url"):
        assert leak not in raw


# --------------------------------------------------------------------------
# Autenticação e provisionamento
# --------------------------------------------------------------------------

def test_missing_identity_is_rejected(client):
    assert client.get("/api/v2/threads").status_code == 401


def test_unprovisioned_principal_is_forbidden(client):
    """Tenant inexistente deve produzir 403 PRINCIPAL_NOT_PROVISIONED."""
    response = client.get("/api/v2/threads", headers=headers(tenant="tenant-ausente"))
    assert response.status_code == 403
    assert response.json()["detail"] == "PRINCIPAL_NOT_PROVISIONED"


def test_user_without_membership_is_forbidden(client):
    """user-2 existe mas não tem membership: acesso negado."""
    response = client.get("/api/v2/threads", headers=headers(user="user-2", roles="member"))
    assert response.status_code == 403
    assert response.json()["detail"] == "PRINCIPAL_NOT_PROVISIONED"


# --------------------------------------------------------------------------
# Listagem de threads
# --------------------------------------------------------------------------

def test_thread_list_is_scoped_and_paginated(client):
    first = client.post("/api/v2/threads", json={"title": "Alfa"}, headers=headers()).json()
    second = client.post("/api/v2/threads", json={"title": "Beta"}, headers=headers()).json()

    body = client.get("/api/v2/threads", headers=headers()).json()
    ids = [item["id"] for item in body["items"]]
    assert first["id"] in ids
    assert second["id"] in ids
    assert body["total"] >= 2
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert all(item["thread_role"] == "owner" for item in body["items"] if item["id"] in ids)


def test_thread_list_pagination_limits(client):
    client.post("/api/v2/threads", json={"title": "Gama"}, headers=headers())
    body = client.get("/api/v2/threads?limit=1&offset=0", headers=headers()).json()
    assert len(body["items"]) == 1
    assert body["limit"] == 1


def test_thread_list_rejects_invalid_limit(client):
    assert client.get("/api/v2/threads?limit=0", headers=headers()).status_code == 422
    assert client.get("/api/v2/threads?limit=999", headers=headers()).status_code == 422


def test_thread_list_has_no_cross_tenant_leak(client):
    """Uma thread criada em outro tenant não aparece na listagem."""
    owned = client.post("/api/v2/threads", json={"title": "Privada"}, headers=headers()).json()
    with Testing() as db:
        if not db.get(User, "user-3"):
            from orkio_v2.models import Tenant

            db.add(Tenant(id="tenant-2", name="Outro"))
            db.add(User(id="user-3", external_subject="sub-3", email="x@example.com", display_name="X"))
            db.add(Membership(tenant_id="tenant-2", user_id="user-3", role="member"))
            db.commit()
    other = client.get("/api/v2/threads", headers=headers(user="user-3", roles="member", tenant="tenant-2")).json()
    assert owned["id"] not in [item["id"] for item in other["items"]]


# --------------------------------------------------------------------------
# Convites: autorização por papel
# --------------------------------------------------------------------------

def test_owner_can_invite(client):
    thread = client.post("/api/v2/threads", json={"title": "Sala"}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/invitations",
        json={"email": "guest@example.com", "role": "participant"},
        headers=headers(),
    )
    assert response.status_code == 200


def _demote(thread_id: str, user_id: str, role: str) -> None:
    with Testing() as db:
        row = db.query(ThreadParticipant).filter_by(thread_id=thread_id, user_id=user_id).one()
        row.thread_role = role
        db.commit()


def test_participant_cannot_invite(client):
    thread = client.post("/api/v2/threads", json={"title": "Sala"}, headers=headers()).json()
    _demote(thread["id"], "user-1", "participant")
    response = client.post(
        f"/api/v2/threads/{thread['id']}/invitations",
        json={"email": "guest@example.com"},
        headers=headers(),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "INVITE_ROLE_REQUIRED"


def test_viewer_cannot_invite(client):
    thread = client.post("/api/v2/threads", json={"title": "Sala"}, headers=headers()).json()
    _demote(thread["id"], "user-1", "viewer")
    response = client.post(
        f"/api/v2/threads/{thread['id']}/invitations",
        json={"email": "guest@example.com"},
        headers=headers(),
    )
    assert response.status_code == 403


def test_moderator_can_invite(client):
    thread = client.post("/api/v2/threads", json={"title": "Sala"}, headers=headers()).json()
    _demote(thread["id"], "user-1", "moderator")
    response = client.post(
        f"/api/v2/threads/{thread['id']}/invitations",
        json={"email": "guest@example.com"},
        headers=headers(),
    )
    assert response.status_code == 200


# --------------------------------------------------------------------------
# LLM fail-closed
# --------------------------------------------------------------------------

def test_message_returns_503_when_llm_not_configured(client):
    """Nunca responder com mensagem falsa de sucesso."""
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/messages",
        json={"content": "oi"},
        headers=headers(),
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "LLM_NOT_CONFIGURED"


def test_no_fake_assistant_message_is_persisted(client):
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    client.post(f"/api/v2/threads/{thread['id']}/messages", json={"content": "oi"}, headers=headers())
    messages = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=headers()).json()
    for message in messages:
        assert "Integração LLM será usada" not in message["content"]
        assert "mensagem recebida com segurança" not in message["content"]


def test_governance_reports_llm_configuration(client):
    body = client.get("/api/v2/governance/status").json()
    assert body["llm_configured"] is False


# --------------------------------------------------------------------------
# Contrato SSE
# --------------------------------------------------------------------------

def _events(raw: str) -> list[str]:
    return [line.removeprefix("event: ").strip() for line in raw.splitlines() if line.startswith("event: ")]


def test_sse_emits_error_and_done_when_llm_missing(client):
    """Erro nunca deixa o input travado: error é sempre seguido de done."""
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/stream",
        json={"content": "oi"},
        headers=headers(),
    )
    events = _events(response.text)
    assert events[-1] == "done"
    assert "error" in events
    assert "LLM_NOT_CONFIGURED" in response.text


def test_sse_always_terminates(client):
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/stream",
        json={"content": "oi"},
        headers=headers(),
    )
    assert _events(response.text).count("done") == 1


def test_sse_sets_no_store(client):
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/stream",
        json={"content": "oi"},
        headers=headers(),
    )
    assert response.headers["cache-control"] == "no-store"


def test_sse_does_not_persist_when_llm_missing(client):
    """Sem LLM configurado, nada é gravado: nem a mensagem do usuário."""
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    client.post(f"/api/v2/threads/{thread['id']}/stream", json={"content": "oi"}, headers=headers())
    messages = client.get(f"/api/v2/threads/{thread['id']}/messages", headers=headers()).json()
    assert messages == []


# --------------------------------------------------------------------------
# Anexos: governança e path traversal
# --------------------------------------------------------------------------

def test_upload_blocked_when_artifacts_disabled(client):
    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/attachments",
        files={"file": ("a.txt", b"conteudo", "text/plain")},
        headers=headers(),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "ARTIFACTS_DISABLED"


def test_upload_traversal_filename_is_sanitized(monkeypatch, client, tmp_path):
    """Com artifacts habilitado, nome com traversal é reduzido ao basename."""
    settings = get_settings()
    monkeypatch.setattr(settings, "artifacts_enabled", True, raising=False)
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path), raising=False)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/attachments",
        files={"file": ("../../etc/passwd", b"x", "text/plain")},
        headers=headers(),
    )
    assert response.status_code == 200
    assert response.json()["filename"] == "passwd"


def test_upload_rejects_disallowed_mime(monkeypatch, client, tmp_path):
    settings = get_settings()
    monkeypatch.setattr(settings, "artifacts_enabled", True, raising=False)
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path), raising=False)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/attachments",
        files={"file": ("a.exe", b"x", "application/x-msdownload")},
        headers=headers(),
    )
    assert response.status_code == 415


def test_upload_rejects_oversized_file(monkeypatch, client, tmp_path):
    settings = get_settings()
    monkeypatch.setattr(settings, "artifacts_enabled", True, raising=False)
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(settings, "max_upload_bytes", 10, raising=False)

    thread = client.post("/api/v2/threads", json={}, headers=headers()).json()
    response = client.post(
        f"/api/v2/threads/{thread['id']}/attachments",
        files={"file": ("a.txt", b"x" * 50, "text/plain")},
        headers=headers(),
    )
    assert response.status_code == 413
