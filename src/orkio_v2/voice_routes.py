from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from .auth import Principal
from .config import Settings, get_settings
from .database import get_db
from .models import ThreadRole
from .routes import _require_console_superadmin, thread_access
from .services.identity import require_provisioned_principal, require_provisioned_superadmin
from .services.speech_to_text import (
    SpeechToTextError,
    inspect_stt_readiness,
    transcribe_audio_bytes,
)


router = APIRouter(prefix="/api/v2")
stt_logger = logging.getLogger("uvicorn.error")

_ALLOWED_AUDIO_TYPES = {
    "audio/webm": ".webm",
    "audio/ogg": ".ogg",
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
    "audio/mp4": ".m4a",
    "audio/x-m4a": ".m4a",
    "audio/mpeg": ".mp3",
    "audio/mp3": ".mp3",
}


_EXPECTED_CONTAINERS = {
    "audio/webm": {"webm"},
    "audio/ogg": {"ogg"},
    "audio/wav": {"wav"},
    "audio/x-wav": {"wav"},
    "audio/mp4": {"mp4"},
    "audio/x-m4a": {"mp4"},
    "audio/mpeg": {"mp3"},
    "audio/mp3": {"mp3"},
}


def _detect_audio_container(raw: bytes) -> str | None:
    if raw.startswith(b"\x1aE\xdf\xa3"):
        return "webm"
    if raw.startswith(b"OggS"):
        return "ogg"
    if len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WAVE":
        return "wav"
    if len(raw) >= 12 and raw[4:8] == b"ftyp":
        return "mp4"
    if raw.startswith(b"ID3"):
        return "mp3"
    if len(raw) >= 2 and raw[0] == 0xFF and (raw[1] & 0xE0) == 0xE0:
        return "mp3"
    return None


def _validate_audio_signature(content_type: str, raw: bytes) -> None:
    detected = _detect_audio_container(raw)
    expected = _EXPECTED_CONTAINERS.get(content_type, set())
    if detected not in expected:
        raise HTTPException(
            415,
            detail={
                "code": "STT_AUDIO_SIGNATURE_MISMATCH",
                "detected": detected or "unknown",
            },
        )


def _raise_stt_error(exc: SpeechToTextError) -> None:
    status_by_code = {
        "STT_DISABLED": 503,
        "STT_DEPENDENCY_NOT_INSTALLED": 503,
        "STT_PROVIDER_UNAVAILABLE": 503,
        "STT_MODEL_UNAVAILABLE": 503,
        "STT_TRANSCRIPTION_FAILED": 502,
        "STT_TIMEOUT": 504,
        "STT_TIMEOUT_NOT_CONFIGURED": 503,
        "STT_CONCURRENCY_LIMIT_NOT_CONFIGURED": 503,
        "STT_CONCURRENCY_LIMIT_REACHED": 429,
        "STT_EMPTY_TRANSCRIPT": 422,
        "STT_LOCALE_NOT_ALLOWED": 422,
    }
    raise HTTPException(
        status_code=status_by_code.get(exc.code, 500),
        detail={"code": exc.code},
    ) from exc


_JOSUE_CEDAR_OPERATOR_HTML = r"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>EFATÀ 777 — Josué / Cedar Voice Pilot</title>
  <style>
    :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; background: #0a0f14; color: #e8eef5; }
    main { max-width: 760px; margin: 40px auto; padding: 0 20px 48px; }
    section { background: #111923; border: 1px solid #263647; border-radius: 16px; padding: 22px; }
    h1 { margin: 0 0 8px; font-size: 24px; }
    p { line-height: 1.5; color: #b8c6d4; }
    .facts { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 16px; margin: 18px 0; }
    .facts div { background: #0d141c; border-radius: 10px; padding: 10px 12px; }
    .facts b { display: block; color: #e8eef5; font-size: 12px; margin-bottom: 4px; }
    button { cursor: pointer; border: 1px solid #3a6b8e; background: #12344a; color: white;
      border-radius: 10px; padding: 11px 14px; margin: 5px 5px 5px 0; font-weight: 650; }
    button.secondary { background: #1b2430; border-color: #415264; }
    button.danger { background: #431d24; border-color: #87404d; }
    button:disabled { opacity: .45; cursor: not-allowed; }
    input { width: 100%; box-sizing: border-box; margin: 12px 0 6px; border-radius: 9px;
      border: 1px solid #415264; background: #0b1118; color: #fff; padding: 11px; }
    audio { width: 100%; margin: 14px 0 4px; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #080d12; border: 1px solid #263647;
      border-radius: 10px; padding: 12px; min-height: 72px; color: #c9d8e7; }
    .ok { color: #80d8a5; } .warn { color: #f1c46e; }
    .small { font-size: 13px; }
  </style>
</head>
<body>
<main>
<section>
  <h1>Josué — Cedar Voice Pilot</h1>
  <p>Operação governada para o agente <b>orkio / Josué / CEO</b>. Esta tela usa somente os endpoints
  administrativos canônicos já existentes. Nenhum SQL direto, migration, bypass de auth ou secret no browser.</p>

  <div class="facts">
    <div><b>Provider</b>OpenAI</div>
    <div><b>Voz</b>cedar</div>
    <div><b>Modelo</b>gpt-4o-mini-tts</div>
    <div><b>Locale</b>pt-BR</div>
    <div><b>Delivery</b>REALTIME_STREAM</div>
    <div><b>Agente</b>orkio</div>
  </div>

  <button id="preview">1. Preparar e ouvir preview</button>
  <audio id="player" controls hidden></audio>

  <p class="small">Após ouvir e aprovar, digite <code>APROVO_CEDAR_JOSUE</code>. A ativação permanece
  fail-closed: se Josué já tiver outra voz ativa, esta tela não a substitui automaticamente.</p>
  <input id="confirmation" autocomplete="off" placeholder="APROVO_CEDAR_JOSUE">
  <button id="activate" disabled>2. Aprovar e ativar Josué</button>
  <button id="refresh" class="secondary">Atualizar capabilities</button>

  <hr style="border-color:#263647;margin:20px 0">
  <p class="small">Rollback explícito: digite <code>ROLLBACK_CEDAR_JOSUE</code> e desative assignment + catálogo.</p>
  <input id="rollbackConfirmation" autocomplete="off" placeholder="ROLLBACK_CEDAR_JOSUE">
  <button id="rollback" class="danger">Rollback</button>

  <pre id="status">Pronto. Nenhuma alteração realizada por esta página ainda.</pre>
</section>
</main>
<script>
(() => {
  "use strict";

  const CATALOG = {
    provider_key: "openai",
    provider_voice_id: "cedar",
    display_name: "Josué CEO — Cedar",
    provider_model: "gpt-4o-mini-tts",
    source_type: "BUILT_IN",
    license_label: "PROVIDER_TERMS",
    cost_class: "API_USAGE_BILLED",
    provenance_url: "https://developers.openai.com/api/docs/guides/text-to-speech",
    catalog_version: "1",
    supported_locales: ["pt-BR"],
    delivery_modes: ["REALTIME_STREAM", "MESSAGE_PLAYBACK"]
  };
  const PREVIEW_TEXT = "Boa tarde. Eu sou Josué, Chief Executive Officer da EFATÀ 777. Nossa prioridade é simples: clareza na decisão, responsabilidade na execução e evidência antes de qualquer conclusão. Temos três objetivos para hoje. Primeiro, proteger a operação. Segundo, remover o principal bloqueio. Terceiro, entregar resultado mensurável.";
  const status = document.getElementById("status");
  const previewButton = document.getElementById("preview");
  const activateButton = document.getElementById("activate");
  const confirmation = document.getElementById("confirmation");
  const rollbackConfirmation = document.getElementById("rollbackConfirmation");
  const player = document.getElementById("player");
  let previewSucceeded = false;
  let currentVoice = null;

  function setStatus(message, kind = "") {
    status.className = kind;
    status.textContent = message;
  }

  function cookie(name) {
    const prefix = name + "=";
    for (const part of document.cookie.split(";")) {
      const item = part.trim();
      if (item.startsWith(prefix)) return decodeURIComponent(item.slice(prefix.length));
    }
    return "";
  }

  function csrf() {
    const value = cookie("patroai_csrf");
    if (!value) throw new Error("CSRF_COOKIE_MISSING — recarregue esta página e tente novamente.");
    return value;
  }

  async function api(path, {method = "GET", body = undefined, expectBlob = false} = {}) {
    const headers = {"Accept": expectBlob ? "audio/mpeg" : "application/json"};
    const options = {method, credentials: "same-origin", headers};
    if (method !== "GET" && method !== "HEAD") {
      headers["X-ORKIO-CSRF"] = csrf();
    }
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    if (!response.ok) {
      let detail = "";
      try {
        const payload = await response.json();
        detail = JSON.stringify(payload.detail ?? payload);
      } catch (_) {
        detail = await response.text();
      }
      throw new Error(`HTTP ${response.status} ${path}: ${detail || response.statusText}`);
    }
    return expectBlob ? response.blob() : response.json();
  }

  function validateCedar(row) {
    if (!row.active) throw new Error("CEDAR_CATALOG_INACTIVE");
    if (row.provider_model !== CATALOG.provider_model) throw new Error("CEDAR_MODEL_MISMATCH");
    if (row.curation_status === "REJECTED") throw new Error("CEDAR_CATALOG_REJECTED");
    const locales = new Set(row.supported_locales || []);
    const modes = new Set(row.delivery_modes || []);
    if (!locales.has("pt-BR")) throw new Error("CEDAR_PT_BR_NOT_SUPPORTED");
    if (!modes.has("REALTIME_STREAM") || !modes.has("MESSAGE_PLAYBACK")) {
      throw new Error("CEDAR_DELIVERY_MODES_MISMATCH");
    }
  }

  async function ensureCedar() {
    const rows = await api("/api/v2/admin/voice-catalog");
    const matches = rows.filter(row =>
      row.provider_key === "openai" && row.provider_voice_id === "cedar"
    );
    if (matches.length > 1) throw new Error("MULTIPLE_CEDAR_CATALOG_ENTRIES");
    if (matches.length === 1) {
      validateCedar(matches[0]);
      return matches[0];
    }
    const created = await api("/api/v2/admin/voice-catalog", {
      method: "POST",
      body: CATALOG
    });
    if (created.curation_status !== "REVIEW_REQUIRED") {
      throw new Error("CEDAR_UNEXPECTED_CURATION_STATUS");
    }
    return created;
  }

  async function doPreview() {
    previewButton.disabled = true;
    activateButton.disabled = true;
    previewSucceeded = false;
    setStatus("Preparando catálogo Cedar e solicitando preview real do provider...");
    try {
      currentVoice = await ensureCedar();
      const blob = await api(`/api/v2/admin/voice-catalog/${encodeURIComponent(currentVoice.id)}/preview`, {
        method: "POST",
        body: {text: PREVIEW_TEXT, locale: "pt-BR"},
        expectBlob: true
      });
      if (blob.type && blob.type !== "audio/mpeg") throw new Error(`PREVIEW_CONTENT_TYPE_UNEXPECTED: ${blob.type}`);
      const oldUrl = player.dataset.objectUrl;
      if (oldUrl) URL.revokeObjectURL(oldUrl);
      const url = URL.createObjectURL(blob);
      player.dataset.objectUrl = url;
      player.src = url;
      player.hidden = false;
      previewSucceeded = true;
      activateButton.disabled = false;
      setStatus(
        `PREVIEW_OK\nvoice_catalog_id=${currentVoice.id}\ncuration_status=${currentVoice.curation_status}\n\nOuça o áudio acima. Nenhum assignment foi ativado.`,
        "ok"
      );
      try { await player.play(); } catch (_) {}
    } catch (error) {
      setStatus(`PREVIEW_FAIL\n${error.message}`, "warn");
    } finally {
      previewButton.disabled = false;
    }
  }

  async function doActivate() {
    if (!previewSucceeded) {
      setStatus("ACTIVATION_BLOCKED — gere e ouça o preview nesta sessão primeiro.", "warn");
      return;
    }
    if (confirmation.value.trim() !== "APROVO_CEDAR_JOSUE") {
      setStatus("ACTIVATION_BLOCKED — confirmação humana literal ausente.", "warn");
      return;
    }
    activateButton.disabled = true;
    setStatus("Aplicando lifecycle governado: APPROVED → DRAFT → VALIDATED → ACTIVE...");
    const evidence = `human-approved-web-preview:${new Date().toISOString()}`;
    try {
      currentVoice = currentVoice || await ensureCedar();

      if (currentVoice.curation_status === "REVIEW_REQUIRED") {
        currentVoice = await api(`/api/v2/admin/voice-catalog/${encodeURIComponent(currentVoice.id)}/curation`, {
          method: "POST",
          body: {curation_status: "APPROVED", evidence_ref: evidence}
        });
      } else if (currentVoice.curation_status !== "APPROVED") {
        throw new Error(`CEDAR_CURATION_NOT_APPROVABLE: ${currentVoice.curation_status}`);
      }

      let assignments = await api("/api/v2/admin/agent-voice-assignments");
      const activeJosue = assignments.filter(row =>
        row.agent_slug === "orkio" && row.locale === "pt-BR" && row.active
      );
      if (activeJosue.some(row => row.voice_catalog_id !== currentVoice.id)) {
        throw new Error("JOSUE_ALREADY_HAS_DIFFERENT_ACTIVE_VOICE — substituição automática bloqueada.");
      }
      if (activeJosue.length > 1) {
        throw new Error("MULTIPLE_ACTIVE_JOSUE_ASSIGNMENTS");
      }

      let assignment = activeJosue[0] || null;
      if (!assignment) {
        assignment = await api("/api/v2/admin/agents/orkio/voice-assignment", {
          method: "PUT",
          body: {
            voice_catalog_id: currentVoice.id,
            locale: "pt-BR",
            delivery_modes: ["REALTIME_STREAM", "MESSAGE_PLAYBACK"],
            presentation_label: "MASCULINA",
            timbre_label: "GRAVE_EXECUTIVO",
            energy_label: "FORTE_CONTROLADA"
          }
        });
      }

      if (assignment.assignment_state === "DRAFT" && assignment.validation_status === "UNVALIDATED") {
        assignment = await api(`/api/v2/admin/agent-voice-assignments/${encodeURIComponent(assignment.id)}/validation`, {
          method: "POST",
          body: {validation_status: "VALIDATED", evidence_ref: evidence}
        });
      }

      if (assignment.assignment_state === "DRAFT" && assignment.validation_status === "VALIDATED") {
        assignment = await api(`/api/v2/admin/agent-voice-assignments/${encodeURIComponent(assignment.id)}/activation`, {
          method: "POST",
          body: {evidence_ref: evidence}
        });
      }

      if (!(assignment.assignment_state === "ACTIVE" && assignment.validation_status === "VALIDATED" && assignment.active)) {
        throw new Error(`ASSIGNMENT_NOT_ACTIVE: ${JSON.stringify({
          state: assignment.assignment_state,
          validation: assignment.validation_status,
          active: assignment.active
        })}`);
      }

      const capability = await api("/api/v2/realtime/capabilities");
      setStatus(
        `ACTIVATION_OK\nvoice_catalog_id=${currentVoice.id}\nassignment_id=${assignment.id}\nassignment_state=${assignment.assignment_state}\nvalidation_status=${assignment.validation_status}\n\ncapability=${JSON.stringify(capability, null, 2)}`,
        "ok"
      );
    } catch (error) {
      setStatus(`ACTIVATION_FAIL\n${error.message}`, "warn");
    } finally {
      activateButton.disabled = !previewSucceeded;
    }
  }

  async function refreshCapabilities() {
    setStatus("Consultando /api/v2/realtime/capabilities...");
    try {
      const capability = await api("/api/v2/realtime/capabilities");
      setStatus(JSON.stringify(capability, null, 2), "ok");
    } catch (error) {
      setStatus(`CAPABILITY_READ_FAIL\n${error.message}`, "warn");
    }
  }

  async function doRollback() {
    if (rollbackConfirmation.value.trim() !== "ROLLBACK_CEDAR_JOSUE") {
      setStatus("ROLLBACK_BLOCKED — confirmação literal ausente.", "warn");
      return;
    }
    setStatus("Executando rollback governado...");
    const evidence = `rollback-web-pilot:${new Date().toISOString()}`;
    try {
      const catalogRows = await api("/api/v2/admin/voice-catalog");
      const cedarRows = catalogRows.filter(row =>
        row.provider_key === "openai" && row.provider_voice_id === "cedar"
      );
      if (cedarRows.length > 1) throw new Error("MULTIPLE_CEDAR_CATALOG_ENTRIES");
      if (cedarRows.length === 0) {
        setStatus("ROLLBACK_OK — catálogo Cedar inexistente; nada a fazer.", "ok");
        return;
      }
      const voice = cedarRows[0];
      const assignments = await api("/api/v2/admin/agent-voice-assignments");
      const matches = assignments.filter(row =>
        row.agent_slug === "orkio" && row.voice_catalog_id === voice.id && row.active
      );
      for (const assignment of matches) {
        await api(`/api/v2/admin/agent-voice-assignments/${encodeURIComponent(assignment.id)}/deactivation`, {
          method: "POST",
          body: {evidence_ref: evidence}
        });
      }
      if (voice.active) {
        await api(`/api/v2/admin/voice-catalog/${encodeURIComponent(voice.id)}/deactivation`, {
          method: "POST",
          body: {evidence_ref: evidence}
        });
      }
      previewSucceeded = false;
      activateButton.disabled = true;
      setStatus("ROLLBACK_OK — assignment Josué/Cedar e catálogo Cedar desativados.", "ok");
    } catch (error) {
      setStatus(`ROLLBACK_FAIL\n${error.message}`, "warn");
    }
  }

  previewButton.addEventListener("click", doPreview);
  activateButton.addEventListener("click", doActivate);
  document.getElementById("refresh").addEventListener("click", refreshCapabilities);
  document.getElementById("rollback").addEventListener("click", doRollback);
})();
</script>
</body>
</html>"""


@router.get("/admin/voice-pilot/josue", response_class=HTMLResponse)
def josue_cedar_voice_pilot_operator(
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
):
    """Authenticated operator page; all writes still use canonical admin APIs."""
    _require_console_superadmin(p, settings)
    return HTMLResponse(
        content=_JOSUE_CEDAR_OPERATOR_HTML,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; "
                "connect-src 'self'; "
                "media-src 'self' blob:; "
                "object-src 'none'; "
                "base-uri 'none'; "
                "frame-ancestors 'none'"
            ),
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    )


@router.get("/voice/stt/readiness")
async def stt_readiness(
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
):
    del p
    result = await asyncio.to_thread(inspect_stt_readiness, settings)
    status = 200 if bool(result.get("ready")) else 503
    return JSONResponse(status_code=status, content=result)


@router.post("/threads/{thread_id}/voice/transcribe")
async def transcribe_voice_message(
    thread_id: str,
    audio: UploadFile = File(...),
    locale: str = Form("auto"),
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _, member = thread_access(db, thread_id, p)
    if member.thread_role == ThreadRole.viewer.value:
        raise HTTPException(403, "THREAD_READ_ONLY")
    if not settings.stt_enabled:
        raise HTTPException(503, detail={"code": "STT_DISABLED"})

    content_type = (audio.content_type or "").split(";", 1)[0].strip().lower()
    suffix = _ALLOWED_AUDIO_TYPES.get(content_type)
    if not suffix:
        raise HTTPException(415, detail={"code": "STT_AUDIO_TYPE_NOT_ALLOWED"})

    raw = await audio.read(settings.stt_max_upload_bytes + 1)
    if not raw:
        raise HTTPException(422, detail={"code": "STT_EMPTY_AUDIO"})
    if len(raw) > settings.stt_max_upload_bytes:
        raise HTTPException(413, detail={"code": "STT_FILE_TOO_LARGE"})
    _validate_audio_signature(content_type, raw)

    try:
        started_at = time.monotonic()
        stt_logger.info(
            "STT_REQUEST_STARTED locale=%s audio_size=%d model=%s",
            locale,
            len(raw),
            settings.stt_model,
        )
        try:
            result = await transcribe_audio_bytes(
                settings,
                raw,
                suffix=suffix,
                locale=locale,
            )
        except SpeechToTextError as exc:
            duration_ms = int((time.monotonic() - started_at) * 1000)
            stt_logger.warning(
                "STT_REQUEST_FAILED code=%s duration_ms=%d locale=%s audio_size=%d model=%s",
                exc.code,
                duration_ms,
                locale,
                len(raw),
                settings.stt_model,
            )
            raise
        else:
            duration_ms = int((time.monotonic() - started_at) * 1000)
            stt_logger.info(
                "STT_REQUEST_COMPLETED duration_ms=%d locale=%s audio_size=%d model=%s",
                duration_ms,
                locale,
                len(raw),
                settings.stt_model,
            )
    except SpeechToTextError as exc:
        _raise_stt_error(exc)

    return {
        "transcript": result.text,
        "locale_requested": locale,
        "language_detected": result.language,
        "language_probability": result.language_probability,
        "engine": result.engine,
        "model": result.model,
        "persisted": False,
    }
