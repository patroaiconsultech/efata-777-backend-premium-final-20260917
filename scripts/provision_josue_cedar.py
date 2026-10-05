#!/usr/bin/env python3
"""
DG-01 — Josué / Cedar governed voice provisioning utility.

Purpose
-------
Use ONLY the existing governed EFATÀ admin APIs to:
  1) create/reuse the OpenAI "cedar" voice catalog entry,
  2) generate a real preview and STOP,
  3) after explicit human approval, approve + validate + activate Josué (agent_slug="orkio"),
  4) optionally roll back through the official deactivation endpoints.

Security / governance
---------------------
- No direct PostgreSQL writes.
- No migration or schema change.
- No auth/tenant/role bypass.
- Uses the existing admin OTP flow and the canonical superadmin-protected endpoints.
- Never prints OTPs, session cookies, tokens, API keys, or provider credentials.
- Default command is "preview"; activation requires an explicit human confirmation string.
- Existing active voice assignment for Josué using another voice causes a fail-closed abort.

Validated against backend archive:
  SHA256: 0a894cf4b25a93e8ed656cb02ce34e67549eb72f1c4da508ed71d6339e4c13b4
  archive embedded Git SHA: ab77820dd9c5093bcdd363e49de5dd78ad04103a

Expected repository path:
  scripts/provision_josue_cedar.py
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request


AGENT_SLUG = "orkio"
AGENT_NAME = "Josué"
VOICE_PROVIDER = "openai"
VOICE_ID = "cedar"
VOICE_MODEL = "gpt-4o-mini-tts"
LOCALE = "pt-BR"
DELIVERY_MODES = ["REALTIME_STREAM", "MESSAGE_PLAYBACK"]

CATALOG_PAYLOAD = {
    "provider_key": VOICE_PROVIDER,
    "provider_voice_id": VOICE_ID,
    "display_name": "Josué CEO — Cedar",
    "provider_model": VOICE_MODEL,
    "source_type": "BUILT_IN",
    "license_label": "PROVIDER_TERMS",
    "cost_class": "API_USAGE_BILLED",
    "provenance_url": "https://developers.openai.com/api/docs/guides/text-to-speech",
    "catalog_version": "1",
    "supported_locales": [LOCALE],
    "delivery_modes": DELIVERY_MODES,
}

ASSIGNMENT_PAYLOAD_TEMPLATE = {
    "locale": LOCALE,
    "delivery_modes": DELIVERY_MODES,
    "presentation_label": "MASCULINA",
    "timbre_label": "GRAVE_EXECUTIVO",
    "energy_label": "FORTE_CONTROLADA",
}

PREVIEW_TEXT = (
    "Boa tarde. Eu sou Josué, Chief Executive Officer da EFATÀ 777. "
    "Nossa prioridade é simples: clareza na decisão, responsabilidade na execução "
    "e evidência antes de qualquer conclusão. Temos três objetivos para hoje. "
    "Primeiro, proteger a operação. Segundo, remover o principal bloqueio. "
    "Terceiro, entregar resultado mensurável."
)

HUMAN_CONFIRMATION = "APROVO_CEDAR_JOSUE"


class ProvisioningError(RuntimeError):
    pass


def _normalize_base_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ProvisioningError("BACKEND_URL_REQUIRED")
    if "://" not in value:
        value = "https://" + value
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https":
        raise ProvisioningError("HTTPS_BACKEND_URL_REQUIRED")
    if not parsed.netloc:
        raise ProvisioningError("INVALID_BACKEND_URL")
    return value.rstrip("/")


def _detect_base_url(cli_value: str | None) -> str:
    value = (
        cli_value
        or os.getenv("EFATA_BACKEND_URL")
        or (
            f"https://{os.getenv('RAILWAY_PUBLIC_DOMAIN')}"
            if os.getenv("RAILWAY_PUBLIC_DOMAIN")
            else None
        )
    )
    if not value:
        value = input("URL HTTPS do backend EFATÀ: ").strip()
    return _normalize_base_url(value)


def _opener() -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def _decode_error_body(data: bytes) -> str:
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except Exception:
        return text[:800]
    if isinstance(parsed, dict):
        detail = parsed.get("detail", parsed)
        return json.dumps(detail, ensure_ascii=False)
    return json.dumps(parsed, ensure_ascii=False)[:800]


def _request(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    method: str,
    path: str,
    payload: dict | None = None,
    *,
    accept: str = "application/json",
    timeout: int = 60,
) -> tuple[bytes, object]:
    url = base_url + path
    data = None
    headers = {
        "Accept": accept,
        "User-Agent": "DG01-Josue-Cedar-Provisioner/1.0",
    }
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with opener.open(req, timeout=timeout) as response:
            return response.read(), response.headers
    except urllib.error.HTTPError as exc:
        body = exc.read()
        detail = _decode_error_body(body)
        raise ProvisioningError(
            f"HTTP_{exc.code} {method} {path}: {detail or exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise ProvisioningError(
            f"NETWORK_ERROR {method} {path}: {exc.reason}"
        ) from exc


def _json_request(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    method: str,
    path: str,
    payload: dict | None = None,
) -> object:
    body, _headers = _request(
        opener,
        base_url,
        method,
        path,
        payload,
        accept="application/json",
    )
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise ProvisioningError(
            f"INVALID_JSON_RESPONSE {method} {path}"
        ) from exc


def _authenticate_admin(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    email: str | None,
) -> None:
    if not email:
        email = input("E-mail administrativo allowlisted: ").strip()
    if not email:
        raise ProvisioningError("ADMIN_EMAIL_REQUIRED")

    # The current backend transport schema still requires a non-empty
    # password field, but admin_otp_start() explicitly discards it. We send
    # a random compatibility value; it is not a credential and is never logged.
    compatibility_value = secrets.token_urlsafe(18)

    start = _json_request(
        opener,
        base_url,
        "POST",
        "/api/v2/auth/admin/otp/start",
        {
            "email": email,
            "password": compatibility_value,
        },
    )
    if not isinstance(start, dict) or not start.get("challenge_token"):
        raise ProvisioningError("OTP_START_INVALID_RESPONSE")

    print("OTP enviado ao e-mail administrativo.")
    code = getpass.getpass("Código OTP de 6 dígitos: ").strip()
    if not re.fullmatch(r"\d{6}", code):
        raise ProvisioningError("OTP_CODE_INVALID")

    verified = _json_request(
        opener,
        base_url,
        "POST",
        "/api/v2/auth/admin/otp/verify",
        {
            "challenge_token": str(start["challenge_token"]),
            "code": code,
        },
    )
    if not isinstance(verified, dict):
        raise ProvisioningError("OTP_VERIFY_INVALID_RESPONSE")

    print("Sessão administrativa autenticada. Nenhum token foi exibido.")


def _get_catalog(
    opener: urllib.request.OpenerDirector,
    base_url: str,
) -> list[dict]:
    rows = _json_request(
        opener, base_url, "GET", "/api/v2/admin/voice-catalog"
    )
    if not isinstance(rows, list):
        raise ProvisioningError("VOICE_CATALOG_INVALID_RESPONSE")
    return [row for row in rows if isinstance(row, dict)]


def _find_cedar(rows: list[dict]) -> dict | None:
    matches = [
        row
        for row in rows
        if row.get("provider_key") == VOICE_PROVIDER
        and row.get("provider_voice_id") == VOICE_ID
    ]
    if len(matches) > 1:
        raise ProvisioningError("MULTIPLE_CEDAR_CATALOG_ENTRIES")
    return matches[0] if matches else None


def _validate_existing_cedar(row: dict) -> None:
    if not row.get("active"):
        raise ProvisioningError("CEDAR_CATALOG_ENTRY_INACTIVE")
    if row.get("provider_model") != VOICE_MODEL:
        raise ProvisioningError(
            "CEDAR_EXISTING_MODEL_MISMATCH: refusing silent mutation"
        )
    locales = set(row.get("supported_locales") or [])
    modes = set(row.get("delivery_modes") or [])
    if LOCALE not in locales:
        raise ProvisioningError(
            "CEDAR_EXISTING_LOCALE_MISMATCH: pt-BR not supported"
        )
    if not set(DELIVERY_MODES).issubset(modes):
        raise ProvisioningError(
            "CEDAR_EXISTING_DELIVERY_MODE_MISMATCH: "
            "REALTIME_STREAM and MESSAGE_PLAYBACK required"
        )
    if row.get("curation_status") == "REJECTED":
        raise ProvisioningError(
            "CEDAR_CATALOG_REJECTED: manual review required"
        )


def _ensure_cedar(
    opener: urllib.request.OpenerDirector,
    base_url: str,
) -> dict:
    current = _find_cedar(_get_catalog(opener, base_url))
    if current is not None:
        _validate_existing_cedar(current)
        print(f"Reutilizando catálogo Cedar existente: {current.get('id')}")
        return current

    created = _json_request(
        opener,
        base_url,
        "POST",
        "/api/v2/admin/voice-catalog",
        CATALOG_PAYLOAD,
    )
    if not isinstance(created, dict) or not created.get("id"):
        raise ProvisioningError("VOICE_CATALOG_CREATE_INVALID_RESPONSE")
    if created.get("curation_status") != "REVIEW_REQUIRED":
        raise ProvisioningError(
            "VOICE_CATALOG_UNEXPECTED_CURATION_STATUS"
        )
    print(f"Catálogo Cedar criado em REVIEW_REQUIRED: {created['id']}")
    return created


def _preview(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    voice: dict,
    preview_file: Path,
) -> None:
    body, headers = _request(
        opener,
        base_url,
        "POST",
        f"/api/v2/admin/voice-catalog/{voice['id']}/preview",
        {"text": PREVIEW_TEXT, "locale": LOCALE},
        accept="audio/mpeg",
        timeout=90,
    )
    content_type = ""
    try:
        content_type = headers.get_content_type()
    except Exception:
        content_type = str(headers.get("Content-Type", "")).split(";", 1)[0].strip()

    if content_type != "audio/mpeg":
        raise ProvisioningError(
            f"VOICE_PREVIEW_UNEXPECTED_CONTENT_TYPE: {content_type!r}"
        )
    if not body:
        raise ProvisioningError("VOICE_PREVIEW_EMPTY")

    preview_file.parent.mkdir(parents=True, exist_ok=True)
    preview_file.write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()

    print("")
    print("PREVIEW GERADO — NENHUMA VOZ FOI ATIVADA.")
    print(f"Arquivo: {preview_file.resolve()}")
    print(f"SHA256:  {digest}")
    print("")
    print(
        "Ouça o MP3. Somente se aprovar, rode o mesmo arquivo no modo "
        f"'activate' com --confirm {HUMAN_CONFIRMATION}."
    )


def _get_assignments(
    opener: urllib.request.OpenerDirector,
    base_url: str,
) -> list[dict]:
    rows = _json_request(
        opener,
        base_url,
        "GET",
        "/api/v2/admin/agent-voice-assignments",
    )
    if not isinstance(rows, list):
        raise ProvisioningError("VOICE_ASSIGNMENTS_INVALID_RESPONSE")
    return [row for row in rows if isinstance(row, dict)]


def _approve_catalog_if_needed(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    voice: dict,
    evidence_ref: str,
) -> dict:
    status = voice.get("curation_status")
    if status == "APPROVED":
        return voice
    if status != "REVIEW_REQUIRED":
        raise ProvisioningError(
            f"VOICE_CATALOG_CANNOT_APPROVE_FROM_{status}"
        )
    approved = _json_request(
        opener,
        base_url,
        "POST",
        f"/api/v2/admin/voice-catalog/{voice['id']}/curation",
        {
            "curation_status": "APPROVED",
            "evidence_ref": evidence_ref,
        },
    )
    if not isinstance(approved, dict) or approved.get("curation_status") != "APPROVED":
        raise ProvisioningError("VOICE_CATALOG_APPROVAL_FAILED")
    return approved


def _ensure_assignment(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    voice: dict,
) -> dict:
    rows = _get_assignments(opener, base_url)
    active_for_josue = [
        row
        for row in rows
        if row.get("agent_slug") == AGENT_SLUG
        and row.get("locale") == LOCALE
        and bool(row.get("active"))
    ]

    if active_for_josue:
        if len(active_for_josue) != 1:
            raise ProvisioningError("MULTIPLE_ACTIVE_JOSUE_VOICE_ASSIGNMENTS")
        existing = active_for_josue[0]
        if existing.get("voice_catalog_id") != voice["id"]:
            raise ProvisioningError(
                "JOSUE_ALREADY_HAS_DIFFERENT_ACTIVE_VOICE: "
                "refusing automatic replacement"
            )
        return existing

    payload = dict(ASSIGNMENT_PAYLOAD_TEMPLATE)
    payload["voice_catalog_id"] = voice["id"]
    created = _json_request(
        opener,
        base_url,
        "PUT",
        f"/api/v2/admin/agents/{AGENT_SLUG}/voice-assignment",
        payload,
    )
    if not isinstance(created, dict) or not created.get("id"):
        raise ProvisioningError("VOICE_ASSIGNMENT_CREATE_INVALID_RESPONSE")
    return created


def _validate_assignment(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    assignment: dict,
    evidence_ref: str,
) -> dict:
    state = assignment.get("assignment_state")
    validation = assignment.get("validation_status")

    if state == "ACTIVE" and validation == "VALIDATED":
        return assignment
    if state != "DRAFT":
        raise ProvisioningError(
            f"VOICE_ASSIGNMENT_NOT_DRAFT: {state}"
        )
    if validation == "FAILED":
        raise ProvisioningError(
            "VOICE_ASSIGNMENT_PREVIOUSLY_FAILED_VALIDATION: "
            "manual investigation required"
        )
    if validation == "VALIDATED":
        return assignment
    if validation != "UNVALIDATED":
        raise ProvisioningError(
            f"VOICE_ASSIGNMENT_UNKNOWN_VALIDATION_STATUS: {validation}"
        )

    updated = _json_request(
        opener,
        base_url,
        "POST",
        f"/api/v2/admin/agent-voice-assignments/{assignment['id']}/validation",
        {
            "validation_status": "VALIDATED",
            "evidence_ref": evidence_ref,
        },
    )
    if not isinstance(updated, dict) or updated.get("validation_status") != "VALIDATED":
        raise ProvisioningError("VOICE_ASSIGNMENT_VALIDATION_FAILED")
    return updated


def _activate_assignment(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    assignment: dict,
    evidence_ref: str,
) -> dict:
    if (
        assignment.get("assignment_state") == "ACTIVE"
        and assignment.get("validation_status") == "VALIDATED"
        and bool(assignment.get("active"))
    ):
        return assignment

    if assignment.get("assignment_state") != "DRAFT":
        raise ProvisioningError(
            f"VOICE_ASSIGNMENT_CANNOT_ACTIVATE_FROM_{assignment.get('assignment_state')}"
        )
    if assignment.get("validation_status") != "VALIDATED":
        raise ProvisioningError("VOICE_ASSIGNMENT_NOT_VALIDATED")

    activated = _json_request(
        opener,
        base_url,
        "POST",
        f"/api/v2/admin/agent-voice-assignments/{assignment['id']}/activation",
        {"evidence_ref": evidence_ref},
    )
    if (
        not isinstance(activated, dict)
        or activated.get("assignment_state") != "ACTIVE"
        or activated.get("validation_status") != "VALIDATED"
        or not bool(activated.get("active"))
    ):
        raise ProvisioningError("VOICE_ASSIGNMENT_ACTIVATION_FAILED")
    return activated


def _activate(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    preview_file: Path,
    confirmation: str | None,
) -> None:
    if confirmation != HUMAN_CONFIRMATION:
        raise ProvisioningError(
            "HUMAN_PREVIEW_APPROVAL_REQUIRED: "
            f"use --confirm {HUMAN_CONFIRMATION}"
        )
    if not preview_file.is_file():
        raise ProvisioningError(
            f"PREVIEW_FILE_NOT_FOUND: {preview_file}"
        )

    digest = hashlib.sha256(preview_file.read_bytes()).hexdigest()
    evidence_ref = f"human-approved-preview-sha256:{digest}"

    voice = _ensure_cedar(opener, base_url)
    voice = _approve_catalog_if_needed(
        opener, base_url, voice, evidence_ref
    )
    assignment = _ensure_assignment(opener, base_url, voice)
    assignment = _validate_assignment(
        opener, base_url, assignment, evidence_ref
    )
    assignment = _activate_assignment(
        opener, base_url, assignment, evidence_ref
    )

    capability = _json_request(
        opener,
        base_url,
        "GET",
        "/api/v2/realtime/capabilities",
    )
    voice_output = (
        capability.get("voice_output")
        if isinstance(capability, dict)
        else None
    )
    runtime_proven = (
        capability.get("runtime_proven")
        if isinstance(capability, dict)
        else None
    )

    print("")
    print("JOSUÉ / CEDAR ATIVADO PELO LIFECYCLE GOVERNADO.")
    print(f"voice_catalog_id: {voice.get('id')}")
    print(f"assignment_id:    {assignment.get('id')}")
    print(f"assignment_state: {assignment.get('assignment_state')}")
    print(f"validation:       {assignment.get('validation_status')}")
    print(f"voice_output:     {json.dumps(voice_output, ensure_ascii=False)}")
    print(f"runtime_proven:   {runtime_proven!r}")
    print("")
    print(
        "Próximo gate: teste Realtime E2E real. "
        "Não trate runtime_proven=False como falha desta ativação; "
        "o snapshot auditado o mantém hardcoded e isso é RT-PROOF-001."
    )


def _rollback(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    confirmation: str | None,
) -> None:
    if confirmation != "ROLLBACK_CEDAR_JOSUE":
        raise ProvisioningError(
            "ROLLBACK_CONFIRMATION_REQUIRED: "
            "use --confirm ROLLBACK_CEDAR_JOSUE"
        )

    voice = _find_cedar(_get_catalog(opener, base_url))
    if voice is None:
        print("Nenhum catálogo Cedar encontrado. Nada a reverter.")
        return

    assignments = _get_assignments(opener, base_url)
    active_matches = [
        row
        for row in assignments
        if row.get("agent_slug") == AGENT_SLUG
        and row.get("voice_catalog_id") == voice.get("id")
        and bool(row.get("active"))
    ]

    evidence_ref = "rollback://josue-cedar-human-approved"

    for assignment in active_matches:
        _json_request(
            opener,
            base_url,
            "POST",
            f"/api/v2/admin/agent-voice-assignments/{assignment['id']}/deactivation",
            {"evidence_ref": evidence_ref},
        )
        print(f"Assignment desativado: {assignment['id']}")

    # The backend refuses catalog deactivation while any active assignment
    # still references it. That fail-closed rule remains authoritative.
    if voice.get("active"):
        _json_request(
            opener,
            base_url,
            "POST",
            f"/api/v2/admin/voice-catalog/{voice['id']}/deactivation",
            {"evidence_ref": evidence_ref},
        )
        print(f"Catálogo Cedar desativado: {voice['id']}")

    print("Rollback governado concluído.")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Provisionamento governado de voz Cedar para Josué (orkio). "
            "Default: apenas cria/reutiliza catálogo e gera preview."
        )
    )
    parser.add_argument(
        "mode",
        nargs="?",
        choices=("preview", "activate", "rollback"),
        default="preview",
    )
    parser.add_argument(
        "--base-url",
        help=(
            "URL HTTPS do backend. Alternativas: EFATA_BACKEND_URL ou "
            "RAILWAY_PUBLIC_DOMAIN."
        ),
    )
    parser.add_argument(
        "--email",
        help="E-mail administrativo allowlisted. Se omitido, será solicitado.",
    )
    parser.add_argument(
        "--preview-file",
        default="josue_cedar_preview.mp3",
        help="Arquivo MP3 do preview (default: josue_cedar_preview.mp3).",
    )
    parser.add_argument(
        "--confirm",
        help=(
            f"Para activate: {HUMAN_CONFIRMATION}. "
            "Para rollback: ROLLBACK_CEDAR_JOSUE."
        ),
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    try:
        base_url = _detect_base_url(args.base_url)
        opener = _opener()
        _authenticate_admin(opener, base_url, args.email)

        preview_file = Path(args.preview_file)

        if args.mode == "preview":
            voice = _ensure_cedar(opener, base_url)
            _preview(opener, base_url, voice, preview_file)
        elif args.mode == "activate":
            _activate(
                opener,
                base_url,
                preview_file,
                args.confirm,
            )
        elif args.mode == "rollback":
            _rollback(opener, base_url, args.confirm)
        else:
            raise ProvisioningError("UNKNOWN_MODE")

        return 0
    except ProvisioningError as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelado pelo operador.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
