from __future__ import annotations

from pathlib import Path
import json

from sqlalchemy import select

from conftest import Testing, headers
from orkio_v2.config import get_settings
from orkio_v2.models import Attachment, AuditEvent, Message, ThreadParticipant
from orkio_v2.services.blob_storage import LocalBlobStorage
from orkio_v2.services.document_context import build_document_context
from orkio_v2.services.unified_document_intake import manifest_key_for_storage


def _configure_intake(monkeypatch, tmp_path, *, threshold=20):
    settings = get_settings()
    monkeypatch.setattr(settings, "unified_document_intake_enabled", True, raising=False)
    monkeypatch.setattr(settings, "artifacts_enabled", True, raising=False)
    monkeypatch.setattr(settings, "artifact_storage_backend", "local", raising=False)
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(
        settings, "document_intake_large_paste_threshold_chars", threshold, raising=False
    )
    monkeypatch.setattr(
        settings, "document_intake_large_paste_max_chars", 5_000_000, raising=False
    )
    monkeypatch.setattr(
        settings, "document_intake_large_paste_max_bytes", 20_000_000, raising=False
    )
    monkeypatch.setattr(settings, "document_intake_manifest_max_bytes", 2_000_000, raising=False)
    monkeypatch.setattr(settings, "document_context_enabled", True, raising=False)
    monkeypatch.setattr(settings, "document_context_max_chars_per_file", 3000, raising=False)
    monkeypatch.setattr(settings, "document_context_max_chars", 6000, raising=False)
    monkeypatch.setattr(settings, "knowledge_chunk_target_chars", 1200, raising=False)
    monkeypatch.setattr(settings, "knowledge_chunk_overlap_chars", 100, raising=False)
    monkeypatch.setattr(settings, "knowledge_retrieval_top_k", 1, raising=False)
    return settings


def _large_markdown():
    return (
        "# Manual Operacional\n"
        "Introdução do documento.\n\n"
        "## Alfa\n"
        + ("banana estabilidade processo alfa operação " * 140)
        + "\n\n## Beta\n"
        + ("financeiro governança compliance contrato beta " * 140)
    )


def test_r3_intake_is_fail_closed_when_disabled(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "unified_document_intake_enabled", False, raising=False)
    monkeypatch.setattr(settings, "artifacts_enabled", True, raising=False)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]

    response = client.post(
        f"/api/v2/threads/{thread_id}/document-intake/paste",
        json={"content": "X" * 100_001, "title": "Grande"},
        headers=headers(),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "DOCUMENT_INTAKE_DISABLED"


def test_r3_small_paste_stays_message_contract_and_is_not_silently_converted(
    client, monkeypatch, tmp_path
):
    _configure_intake(monkeypatch, tmp_path, threshold=100)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]

    response = client.post(
        f"/api/v2/threads/{thread_id}/document-intake/paste",
        json={"content": "small paste", "title": "Pequeno"},
        headers=headers(),
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "PASTE_BELOW_DOCUMENT_THRESHOLD"

    # Existing message endpoint remains the canonical small-paste path.
    from orkio_v2.schemas import MessageCreate
    field = MessageCreate.model_fields["content"]
    assert field.metadata
    assert any(getattr(item, "max_length", None) == 100000 for item in field.metadata)


def test_r3_large_paste_creates_thread_bound_canonical_markdown_and_manifest(
    client, monkeypatch, tmp_path
):
    _configure_intake(monkeypatch, tmp_path)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    content = _large_markdown()

    response = client.post(
        f"/api/v2/threads/{thread_id}/document-intake/paste",
        json={"content": content, "title": "Manual colado"},
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["intake_status"] == "ready"
    assert body["source_kind"] == "LARGE_PASTE"
    assert body["context_mode"] == "selective"
    assert body["source_chars"] == len(content)
    assert body["canonical_chars"] > body["source_chars"]
    assert body["sections"] >= 3
    assert body["chunks"] >= 3
    assert body["reused"] is False

    with Testing() as db:
        attachment = db.get(Attachment, body["attachment_id"])
        assert attachment is not None
        assert attachment.tenant_id == "tenant-1"
        assert attachment.thread_id == thread_id
        assert attachment.mime_type == "text/markdown"
        assert attachment.sha256 == body["canonical_sha256"]
        assert db.scalar(
            select(Message).where(
                Message.thread_id == thread_id,
                Message.content == content,
            )
        ) is None
        audit = db.scalar(
            select(AuditEvent).where(
                AuditEvent.resource_type == "attachment",
                AuditEvent.resource_id == attachment.id,
                AuditEvent.action == "document_intake.paste.ready",
            )
        )
        assert audit is not None
        assert audit.metadata_json["thread_id"] == thread_id

    storage = LocalBlobStorage(tmp_path)
    canonical = storage.get(attachment.storage_key)
    assert canonical.startswith(b"# paste-")
    manifest = json.loads(
        storage.get(manifest_key_for_storage(attachment.storage_key)).decode("utf-8")
    )
    assert manifest["tenant_id"] == "tenant-1"
    assert manifest["thread_id"] == thread_id
    assert manifest["source_chars"] == len(content)
    assert len(manifest["chunks"]) == body["chunks"]


def test_r3_same_large_paste_is_idempotently_reused(client, monkeypatch, tmp_path):
    _configure_intake(monkeypatch, tmp_path)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    payload = {"content": _large_markdown(), "title": "Mesmo conteúdo"}

    first = client.post(
        f"/api/v2/threads/{thread_id}/document-intake/paste",
        json=payload,
        headers=headers(),
    )
    second = client.post(
        f"/api/v2/threads/{thread_id}/document-intake/paste",
        json=payload,
        headers=headers(),
    )
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["attachment_id"] == second.json()["attachment_id"]
    assert first.json()["canonical_sha256"] == second.json()["canonical_sha256"]
    assert second.json()["reused"] is True


def test_r3_selective_context_uses_manifest_ranges_not_full_canonical_get(
    client, monkeypatch, tmp_path
):
    settings = _configure_intake(monkeypatch, tmp_path)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]

    created = client.post(
        f"/api/v2/threads/{thread_id}/document-intake/paste",
        json={"content": _large_markdown(), "title": "Seleção"},
        headers=headers(),
    )
    assert created.status_code == 200, created.text

    base = LocalBlobStorage(tmp_path)
    calls = {"manifest_get": 0, "range": 0, "canonical_get": 0}

    class ObservedStorage:
        def get(self, key):
            if key.endswith(".intake-v1.json"):
                calls["manifest_get"] += 1
                return base.get(key)
            calls["canonical_get"] += 1
            raise AssertionError("full canonical blob get must not occur for indexed paste")

        def read_range(self, key, start, end):
            calls["range"] += 1
            return base.read_range(key, start, end)

    monkeypatch.setattr(
        "orkio_v2.services.document_context.build_blob_storage",
        lambda _settings: ObservedStorage(),
    )

    with Testing() as db:
        bundle = build_document_context(
            db,
            settings=settings,
            tenant_id="tenant-1",
            thread_id=thread_id,
            query_text="financeiro governança compliance",
        )
    assert bundle is not None
    text = bundle.message["content"]
    assert "financeiro" in text
    assert "governança" in text
    assert "banana estabilidade" not in text
    assert calls["manifest_get"] >= 1
    assert calls["range"] >= 1
    assert calls["canonical_get"] == 0
    assert bundle.provenance.truncated is True


def test_r3_thread_isolation_prevents_paste_context_leak(
    client, monkeypatch, tmp_path
):
    settings = _configure_intake(monkeypatch, tmp_path)
    thread_a = client.post("/api/v2/threads", json={"title": "A"}, headers=headers()).json()["id"]
    thread_b = client.post("/api/v2/threads", json={"title": "B"}, headers=headers()).json()["id"]

    response = client.post(
        f"/api/v2/threads/{thread_a}/document-intake/paste",
        json={"content": _large_markdown(), "title": "Somente A"},
        headers=headers(),
    )
    assert response.status_code == 200, response.text

    with Testing() as db:
        context_a = build_document_context(
            db,
            settings=settings,
            tenant_id="tenant-1",
            thread_id=thread_a,
            query_text="financeiro",
        )
        context_b = build_document_context(
            db,
            settings=settings,
            tenant_id="tenant-1",
            thread_id=thread_b,
            query_text="financeiro",
        )

    assert context_a is not None
    assert "financeiro" in context_a.message["content"]
    assert context_b is None


def test_r3_viewer_cannot_create_large_paste_document(
    client, monkeypatch, tmp_path
):
    _configure_intake(monkeypatch, tmp_path)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]

    with Testing() as db:
        participant = db.scalar(
            select(ThreadParticipant).where(
                ThreadParticipant.thread_id == thread_id,
                ThreadParticipant.user_id == "user-1",
            )
        )
        assert participant is not None
        participant.thread_role = "viewer"
        participant.can_upload_files = True
        db.commit()

    response = client.post(
        f"/api/v2/threads/{thread_id}/document-intake/paste",
        json={"content": _large_markdown(), "title": "Negado"},
        headers=headers(),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "THREAD_READ_ONLY"


def test_r3_tampered_manifest_fails_closed_without_supplying_content(
    client, monkeypatch, tmp_path
):
    settings = _configure_intake(monkeypatch, tmp_path)
    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]

    created = client.post(
        f"/api/v2/threads/{thread_id}/document-intake/paste",
        json={"content": _large_markdown(), "title": "Manifest"},
        headers=headers(),
    )
    assert created.status_code == 200, created.text

    with Testing() as db:
        attachment = db.get(Attachment, created.json()["attachment_id"])
        assert attachment is not None
        manifest_path = (
            Path(settings.artifact_storage_path)
            / manifest_key_for_storage(attachment.storage_key)
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["canonical_sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        bundle = build_document_context(
            db,
            settings=settings,
            tenant_id="tenant-1",
            thread_id=thread_id,
            query_text="financeiro",
        )

    assert bundle is not None
    assert bundle.provenance.available is False
    assert bundle.provenance.extraction_status == "failed"
    assert "DOCUMENT_INTAKE_MANIFEST_INVALID" in bundle.message["content"]


def test_r3_chat_history_consumes_relevant_paste_chunks(
    client, monkeypatch, tmp_path
):
    settings = _configure_intake(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "openai_api_key", "r3-test-key-not-real", raising=False)

    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    created = client.post(
        f"/api/v2/threads/{thread_id}/document-intake/paste",
        json={"content": _large_markdown(), "title": "Chat seletivo"},
        headers=headers(),
    )
    assert created.status_code == 200, created.text

    captured = {}

    async def fake_generate(_settings, agent, history):
        captured["agent"] = agent
        captured["history"] = history
        return "Resposta baseada no documento."

    monkeypatch.setattr("orkio_v2.routes.llm.generate", fake_generate)

    response = client.post(
        f"/api/v2/threads/{thread_id}/messages",
        json={"content": "Explique o trecho financeiro sobre governança e compliance.", "agent": "Josué"},
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    joined = "\n".join(str(item.get("content") or "") for item in captured["history"])
    assert "financeiro" in joined
    assert "governança" in joined
    assert "banana estabilidade" not in joined
    assert response.json()["content"] == "Resposta baseada no documento."


def test_r3_document_intake_capabilities_are_backend_authoritative(
    client, monkeypatch, tmp_path
):
    settings = _configure_intake(monkeypatch, tmp_path, threshold=12345)
    monkeypatch.setattr(
        settings, "document_intake_large_paste_max_chars", 234567, raising=False
    )
    response = client.get("/api/v2/document-intake/capabilities", headers=headers())
    assert response.status_code == 200
    cap = response.json()["large_paste"]
    assert cap["supported"] is True
    assert cap["enabled"] is True
    assert cap["threshold_chars"] == 12345
    assert cap["max_chars"] == 234567
    assert cap["canonical_format"] == "text/markdown"
    assert cap["context_mode"] == "selective"
    assert cap["requires_explicit_confirmation"] is True


def test_r3_team_runtime_passes_latest_user_query_to_document_context(
    client, monkeypatch
):
    from orkio_v2.services import team_runtime

    thread_id = client.post("/api/v2/threads", json={}, headers=headers()).json()["id"]
    with Testing() as db:
        db.add(
            Message(
                tenant_id="tenant-1",
                thread_id=thread_id,
                author_type="user",
                author_id="user-1",
                content="Pergunta financeira de governança para o Team",
            )
        )
        db.commit()

    captured = {}

    def fake_context(db, *, settings, tenant_id, thread_id, query_text=""):
        captured["query_text"] = query_text
        return None

    monkeypatch.setattr(team_runtime, "document_context_message", fake_context)

    with Testing() as db:
        team_runtime.team_history(
            db,
            thread_id=thread_id,
            tenant_id="tenant-1",
            settings=get_settings(),
        )

    assert captured["query_text"] == "Pergunta financeira de governança para o Team"
