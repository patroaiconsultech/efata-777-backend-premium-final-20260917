from __future__ import annotations

from pathlib import Path

from orkio_v2.config import get_settings
from orkio_v2.services.knowledge_retrieval import build_knowledge_context
from conftest import Testing, headers


FOUNDER_FILE = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "knowledge"
    / "EFATA777_FOUNDER_PROFILE_DANIEL_GRAEBIN_v1_3.md"
)


def test_founder_knowledge_can_be_published_and_retrieved_for_orkio_realtime(
    client, tmp_path, monkeypatch
):
    cfg = get_settings()
    monkeypatch.setattr(cfg, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(cfg, "knowledge_plane_enabled", True, raising=False)
    monkeypatch.setattr(cfg, "large_document_pipeline_enabled", False, raising=False)

    payload = FOUNDER_FILE.read_bytes()

    uploaded = client.post(
        "/api/v2/knowledge",
        headers=headers(),
        data={
            "scope": "INSTITUTIONAL",
            "title": "EFATÀ 777 — Founder Profile — Daniel Graebin",
            "classification": "internal",
            "allowed_purposes": "chat,team,realtime",
            "agent_id": "orkio",
        },
        files={
            "file": (
                FOUNDER_FILE.name,
                payload,
                "text/markdown",
            )
        },
    )
    assert uploaded.status_code == 200, uploaded.text
    created = uploaded.json()
    assert created["status"] == "DRAFT"
    assert created["scope"] == "INSTITUTIONAL"
    assert created["agent_id"] == "orkio"
    assert created["classification"] == "internal"
    assert created["allowed_purposes"] == ["chat", "team", "realtime"]
    assert created["sha256"] == "1a6f9ffae454ef310c0be07381dcb530a0d3e711b9df71acce8584f70aaaaedd"

    published = client.post(
        f"/api/v2/knowledge/{created['id']}/publish",
        headers=headers(),
    )
    assert published.status_code == 200, published.text
    assert published.json()["status"] == "ACTIVE"

    with Testing() as db:
        bundle = build_knowledge_context(
            db,
            settings=cfg,
            tenant_id="tenant-1",
            user_id="user-1",
            purpose="realtime",
            execution_id="exec-founder-realtime",
            thread_id="thread-founder",
            agent_id="orkio",
            query_text="Quem é o Founder da EFATÀ 777?",
        )
        assert bundle is not None
        joined = "\n".join(message["content"] for message in bundle.messages)
        assert "Daniel Graebin é o Founder & CEO da PatroAI Consultech" in joined
        assert "fundador da plataforma EFATÀ 777" in joined
        assert "GOVERNED KNOWLEDGE LAYER — AGENT_SCOPED" in joined
        assert all(message["role"] == "user" for message in bundle.messages)

        other_agent = build_knowledge_context(
            db,
            settings=cfg,
            tenant_id="tenant-1",
            user_id="user-1",
            purpose="realtime",
            execution_id="exec-founder-other-agent",
            thread_id="thread-founder",
            agent_id="different-agent",
            query_text="Quem é o Founder da EFATÀ 777?",
        )
        if other_agent is not None:
            other_joined = "\n".join(
                message["content"] for message in other_agent.messages
            )
            assert "fundador da plataforma EFATÀ 777" not in other_joined
