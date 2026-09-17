from __future__ import annotations

import asyncio
import logging
import os
import re
import smtplib
import ssl
import threading
import time
import uuid
from collections import defaultdict, deque
from email.message import EmailMessage
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

router = APIRouter(prefix="/api/public", tags=["public-applications"])
logger = logging.getLogger(__name__)

MAX_RESUME_BYTES = 10 * 1024 * 1024
RATE_WINDOW_SECONDS = 30 * 60
RATE_MAX_REQUESTS = 5

_ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx"}
_ALLOWED_CONTENT_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/octet-stream",
}
_APPLICATION_TYPES = {"career", "consultant"}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

_rate_lock = threading.Lock()
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)


def _clean(value: str | None, limit: int) -> str:
    return (value or "").strip()[:limit]


def _rate_key(request: Request, email: str) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{host}|{email.strip().lower()}"


def _enforce_rate_limit(key: str) -> None:
    now = time.monotonic()
    with _rate_lock:
        bucket = _rate_buckets[key]
        while bucket and now - bucket[0] > RATE_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= RATE_MAX_REQUESTS:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "PUBLIC_APPLICATION_RATE_LIMITED",
                    "message": "Muitas tentativas. Aguarde alguns minutos e tente novamente.",
                },
            )
        bucket.append(now)


def _safe_filename(filename: str | None) -> str:
    name = Path(filename or "curriculo").name
    name = _SAFE_FILENAME_RE.sub("_", name)
    return name[:120] or "curriculo"


def _validate_resume(filename: str, content_type: str, content: bytes) -> None:
    extension = Path(filename).suffix.lower()
    if extension not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail={
                "code": "PUBLIC_APPLICATION_RESUME_TYPE_UNSUPPORTED",
                "message": "Envie o currículo em PDF, DOC ou DOCX.",
            },
        )
    if content_type and content_type not in _ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=415,
            detail={
                "code": "PUBLIC_APPLICATION_RESUME_TYPE_UNSUPPORTED",
                "message": "Formato de currículo não suportado.",
            },
        )

    valid_signature = (
        extension == ".pdf" and content.startswith(b"%PDF")
    ) or (
        extension == ".doc" and content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    ) or (
        extension == ".docx"
        and content.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
    )
    if not valid_signature:
        raise HTTPException(
            status_code=415,
            detail={
                "code": "PUBLIC_APPLICATION_RESUME_SIGNATURE_INVALID",
                "message": "O arquivo enviado não corresponde ao formato informado.",
            },
        )


def _smtp_settings() -> dict[str, str | int | bool]:
    host = os.getenv("PATROAI_APPLICATION_SMTP_HOST", "").strip()
    from_email = os.getenv("PATROAI_APPLICATION_SMTP_FROM", "").strip()
    if not host or not from_email:
        raise RuntimeError("application email transport not configured")

    try:
        port = int(os.getenv("PATROAI_APPLICATION_SMTP_PORT", "587").strip())
    except ValueError as exc:
        raise RuntimeError("invalid application smtp port") from exc

    return {
        "host": host,
        "port": port,
        "username": os.getenv("PATROAI_APPLICATION_SMTP_USERNAME", "").strip(),
        "password": os.getenv("PATROAI_APPLICATION_SMTP_PASSWORD", ""),
        "from_email": from_email,
        "to_email": os.getenv("PATROAI_APPLICATION_TO_EMAIL", "Daniel@Patroai.com").strip(),
        "starttls": os.getenv("PATROAI_APPLICATION_SMTP_STARTTLS", "true").strip().lower()
        not in {"0", "false", "no"},
        "ssl": os.getenv("PATROAI_APPLICATION_SMTP_SSL", "false").strip().lower()
        in {"1", "true", "yes"},
    }


def _deliver_application(
    *,
    application_id: str,
    application_type: str,
    full_name: str,
    email: str,
    phone: str,
    location: str,
    linkedin_url: str,
    portfolio_url: str,
    interest_area: str,
    experience_years: str,
    availability: str,
    consulting_specialty: str,
    consulting_experience: str,
    introduction: str,
    filename: str,
    resume_content: bytes,
) -> None:
    settings = _smtp_settings()
    kind = "Novo Consultor" if application_type == "consultant" else "Candidatura"
    safe_interest = re.sub(r"[\r\n]+", " ", interest_area).strip()[:100]
    safe_name = re.sub(r"[\r\n]+", " ", full_name).strip()[:100]

    message = EmailMessage()
    message["Subject"] = f"[PatroAI] {kind} — {safe_interest} — {safe_name}"
    message["From"] = str(settings["from_email"])
    message["To"] = str(settings["to_email"])
    message["Reply-To"] = email
    message.set_content(
        "\n".join(
            [
                "Nova candidatura recebida pela landing PatroAI.",
                "",
                f"ID: {application_id}",
                f"Tipo: {application_type}",
                f"Nome: {full_name}",
                f"E-mail: {email}",
                f"Telefone / WhatsApp: {phone}",
                f"Cidade / Estado: {location}",
                f"Área de interesse: {interest_area}",
                f"Anos de experiência: {experience_years or '-'}",
                f"Disponibilidade: {availability or '-'}",
                f"LinkedIn: {linkedin_url or '-'}",
                f"Portfólio / GitHub / Site: {portfolio_url or '-'}",
                f"Especialidade consultiva: {consulting_specialty or '-'}",
                "",
                "Experiência consultiva / IA:",
                consulting_experience or "-",
                "",
                "Apresentação profissional:",
                introduction,
                "",
                "Consentimento para análise da candidatura: confirmado.",
            ]
        )
    )
    message.add_attachment(
        resume_content,
        maintype="application",
        subtype="octet-stream",
        filename=filename,
    )

    context = ssl.create_default_context()
    if bool(settings["ssl"]):
        smtp = smtplib.SMTP_SSL(
            str(settings["host"]),
            int(settings["port"]),
            timeout=20,
            context=context,
        )
    else:
        smtp = smtplib.SMTP(
            str(settings["host"]),
            int(settings["port"]),
            timeout=20,
        )

    with smtp:
        if bool(settings["starttls"]) and not bool(settings["ssl"]):
            smtp.starttls(context=context)
        username = str(settings["username"])
        if username:
            smtp.login(username, str(settings["password"]))
        smtp.send_message(message)


@router.post("/applications")
async def submit_public_application(
    request: Request,
    application_type: str = Form(...),
    full_name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    location: str = Form(...),
    interest_area: str = Form(...),
    introduction: str = Form(...),
    consent: str = Form(...),
    resume: UploadFile = File(...),
    linkedin_url: str = Form(""),
    portfolio_url: str = Form(""),
    experience_years: str = Form(""),
    availability: str = Form(""),
    consulting_specialty: str = Form(""),
    consulting_experience: str = Form(""),
    website: str = Form(""),
) -> dict[str, object]:
    if _clean(website, 200):
        return {"ok": True, "application_id": uuid.uuid4().hex}

    application_type = _clean(application_type, 24).lower()
    full_name = _clean(full_name, 120)
    email = _clean(email, 160).lower()
    phone = _clean(phone, 40)
    location = _clean(location, 120)
    interest_area = _clean(interest_area, 180)
    introduction = _clean(introduction, 1800)
    linkedin_url = _clean(linkedin_url, 300)
    portfolio_url = _clean(portfolio_url, 300)
    experience_years = _clean(experience_years, 40)
    availability = _clean(availability, 120)
    consulting_specialty = _clean(consulting_specialty, 180)
    consulting_experience = _clean(consulting_experience, 1200)

    if application_type not in _APPLICATION_TYPES:
        raise HTTPException(
            status_code=422,
            detail={"code": "PUBLIC_APPLICATION_TYPE_INVALID", "message": "Tipo de candidatura inválido."},
        )
    if not all([full_name, email, phone, location, interest_area, introduction]):
        raise HTTPException(
            status_code=422,
            detail={"code": "PUBLIC_APPLICATION_REQUIRED_FIELDS", "message": "Preencha os campos obrigatórios."},
        )
    if not _EMAIL_RE.match(email):
        raise HTTPException(
            status_code=422,
            detail={"code": "PUBLIC_APPLICATION_EMAIL_INVALID", "message": "Informe um e-mail válido."},
        )
    if application_type == "consultant" and not consulting_specialty:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "PUBLIC_APPLICATION_CONSULTING_SPECIALTY_REQUIRED",
                "message": "Informe sua especialidade de consultoria.",
            },
        )
    if _clean(consent, 12).lower() not in {"true", "1", "yes", "on"}:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "PUBLIC_APPLICATION_CONSENT_REQUIRED",
                "message": "O consentimento é necessário para enviar a candidatura.",
            },
        )

    _enforce_rate_limit(_rate_key(request, email))

    filename = _safe_filename(resume.filename)
    content_type = (resume.content_type or "application/octet-stream").lower()
    content = await resume.read(MAX_RESUME_BYTES + 1)
    await resume.close()

    if len(content) > MAX_RESUME_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "code": "PUBLIC_APPLICATION_RESUME_TOO_LARGE",
                "message": "O currículo deve ter no máximo 10 MB.",
            },
        )
    if not content:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "PUBLIC_APPLICATION_RESUME_EMPTY",
                "message": "O currículo enviado está vazio.",
            },
        )

    _validate_resume(filename, content_type, content)

    application_id = uuid.uuid4().hex
    try:
        await asyncio.to_thread(
            _deliver_application,
            application_id=application_id,
            application_type=application_type,
            full_name=full_name,
            email=email,
            phone=phone,
            location=location,
            linkedin_url=linkedin_url,
            portfolio_url=portfolio_url,
            interest_area=interest_area,
            experience_years=experience_years,
            availability=availability,
            consulting_specialty=consulting_specialty,
            consulting_experience=consulting_experience,
            introduction=introduction,
            filename=filename,
            resume_content=content,
        )
    except Exception as exc:
        logger.warning(
            "public_application_delivery_failed application_id=%s error_type=%s",
            application_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=503,
            detail={
                "code": "PUBLIC_APPLICATION_DELIVERY_UNAVAILABLE",
                "message": "Não foi possível enviar a candidatura agora. Tente novamente em instantes.",
            },
        ) from exc

    return {"ok": True, "application_id": application_id}
