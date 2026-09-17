import hashlib
import io
from pathlib import Path

import pytest

from conftest import Testing, headers
from orkio_v2.services.artifact_generation import (
    DOCX_MIME,
    JSON_MIME,
    MARKDOWN_MIME,
    PDF_MIME,
    PPTX_MIME,
    XLSX_MIME,
    detect_artifact_intent,
    render_and_validate,
    _pdf_bytes,
    _pptx_bytes,
    _xlsx_bytes,
)
from orkio_v2.auth import Principal
from orkio_v2.config import get_settings
from orkio_v2.models import Membership
from orkio_v2.services import llm
from orkio_v2.routes import _effective_agent_target
from orkio_v2.realtime_routes import _effective_direct_agent
from orkio_v2.services.document_context import extract_document_text


@pytest.mark.parametrize(
    ("phrase", "requested_format", "extension"),
    [
        ("gere um relatório em PDF", "pdf", ".pdf"),
        ("exporte uma apresentação PowerPoint", "pptx", ".pptx"),
        ("crie um arquivo Markdown", "markdown", ".md"),
        ("salve os dados em JSON", "json", ".json"),
        ("gere uma planilha Excel", "xlsx", ".xlsx"),
        ("gere um documento Word", "docx", ".docx"),
    ],
)
def test_artifact_intent_supports_product_formats(phrase, requested_format, extension):
    intent = detect_artifact_intent(phrase)
    assert intent is not None
    assert intent.requested_format == requested_format
    assert intent.extension == extension


@pytest.mark.parametrize(
    ("phrase", "filename", "mime_type"),
    [
        ("gere um PDF", "briefing.pdf", PDF_MIME),
        ("gere um PPTX", "briefing.pptx", PPTX_MIME),
        ("gere um Markdown", "briefing.md", MARKDOWN_MIME),
        ("gere um JSON", "briefing.json", JSON_MIME),
        ("gere uma planilha Excel", "briefing.xlsx", XLSX_MIME),
    ],
)
def test_artifact_renderers_reopen_and_validate(phrase, filename, mime_type):
    intent = detect_artifact_intent(phrase)
    assert intent is not None
    content = '{"project": "Efata", "status": "validated"}' if mime_type == JSON_MIME else "Resumo executivo Efata 777."
    if mime_type == XLSX_MIME:
        content = "Indicador | Status\nProjetos | Validado"
    result = render_and_validate(intent=intent, content=content, filename=filename)
    assert result.mime_type == mime_type
    assert result.sha256 == hashlib.sha256(result.data).hexdigest()
    assert result.semantic_text


def test_xlsx_renderer_accepts_markdown_table_separator():
    intent = detect_artifact_intent("gere uma planilha Excel")
    assert intent is not None
    result = render_and_validate(
        intent=intent,
        content="| Indicador | Status |\n|---|:---:|\n| Projetos | Validado |",
        filename="indicadores.xlsx",
    )
    assert result.mime_type == XLSX_MIME
    assert "Indicador" in result.semantic_text
    assert "Validado" in result.semantic_text


def test_document_context_reads_markdown_json_pptx_and_pdf():
    assert extract_document_text(
        filename="briefing.md",
        mime_type=MARKDOWN_MIME,
        raw=b"# Efata\n\nConteudo de teste.",
        max_chars=1000,
        max_pdf_pages=10,
    ).startswith("# Efata")
    assert "\"status\": \"ready\"" in extract_document_text(
        filename="briefing.json",
        mime_type=JSON_MIME,
        raw=b'{"status":"ready"}',
        max_chars=1000,
        max_pdf_pages=10,
    )
    pptx = _pptx_bytes("PPTX-EFATA-MARKER")
    assert "PPTX-EFATA-MARKER" in extract_document_text(
        filename="briefing.pptx",
        mime_type=PPTX_MIME,
        raw=pptx,
        max_chars=1000,
        max_pdf_pages=10,
    )
    xlsx = _xlsx_bytes("Indicador | Status\nProjetos | XLSX-EFATA-MARKER")
    assert "XLSX-EFATA-MARKER" in extract_document_text(
        filename="briefing.xlsx",
        mime_type=XLSX_MIME,
        raw=xlsx,
        max_chars=1000,
        max_pdf_pages=10,
    )
    pdf = _pdf_bytes("PDF-EFATA-MARKER")
    assert "PDF-EFATA-MARKER" in extract_document_text(
        filename="briefing.pdf",
        mime_type=PDF_MIME,
        raw=pdf,
        max_chars=1000,
        max_pdf_pages=10,
    )


def test_owner_can_rename_thread_and_read_updated_title(client):
    thread = client.post(
        "/api/v2/threads",
        json={"title": "Nova conversa"},
        headers=headers(),
    ).json()
    renamed = client.patch(
        f"/api/v2/threads/{thread['id']}",
        json={"title": "Plano de impacto Efata"},
        headers=headers(),
    )
    assert renamed.status_code == 200
    assert renamed.json()["title"] == "Plano de impacto Efata"
    listed = client.get("/api/v2/threads", headers=headers()).json()["items"]
    assert next(item for item in listed if item["id"] == thread["id"])["title"] == "Plano de impacto Efata"


def test_common_agent_guards_preserve_technical_namespace():
    principal = Principal(user_id="user-1", tenant_id="tenant-1", roles=("member",))
    assert _effective_agent_target("id:admin-agent", principal) == "id:orkio"
    assert _effective_direct_agent("id:admin-agent", principal) == "id:orkio"


def test_common_member_stream_resolves_co_creator(client, monkeypatch):
    with Testing() as db:
        db.add(Membership(tenant_id="tenant-1", user_id="user-2", role="member"))
        db.commit()

    try:
        monkeypatch.setattr(get_settings(), "openai_api_key", "test-key-not-real", raising=False)

        async def fake_stream(settings, agent, history):
            assert agent == "orkio"
            yield "Resposta do Co-Criador."

        monkeypatch.setattr(llm, "stream", fake_stream)
        thread = client.post("/api/v2/threads", json={}, headers=headers(user="user-2", roles="member")).json()
        response = client.post(
            f"/api/v2/threads/{thread['id']}/stream",
            json={"content": "Teste de chat comum", "agent": "id:orkio"},
            headers=headers(user="user-2", roles="member"),
        )
        assert response.status_code == 200
        assert '"agent_id": "orkio"' in response.text
        assert 'event: done' in response.text
    finally:
        with Testing() as db:
            db.query(Membership).filter(
                Membership.tenant_id == "tenant-1",
                Membership.user_id == "user-2",
            ).delete()
            db.commit()


def test_governance_guards_are_present_for_common_agent_and_thread_rename():
    routes = Path(__file__).parents[1] / "src/orkio_v2/routes.py"
    text = routes.read_text(encoding="utf-8")
    assert 'catalog = tuple(agent for agent in catalog if agent.slug.lower() == "orkio")' in text
    assert 'def _effective_agent_target(requested_target: str, p: Principal) -> str:' in text
    assert '@router.patch("/threads/{thread_id}")' in text
    assert 'THREAD_RENAME_ROLE_REQUIRED' in text
