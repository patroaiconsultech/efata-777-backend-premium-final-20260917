from __future__ import annotations

import json
import logging
import ssl
from urllib import request as urllib_request

from ..config import Settings

logger = logging.getLogger(__name__)


class EmailDeliveryError(Exception):
    pass


def send_resend_email(
    *,
    settings: Settings,
    to_email: str,
    subject: str,
    text_body: str,
    html_body: str | None = None,
    idempotency_key: str | None = None,
) -> str | None:
    api_key = settings.resend_api_key.strip()
    from_email = settings.resend_from.strip()
    recipient = to_email.strip()
    if not api_key:
        raise EmailDeliveryError("RESEND_API_KEY_MISSING")
    if not from_email or "@" not in from_email:
        raise EmailDeliveryError("RESEND_FROM_INVALID")
    if not recipient or "@" not in recipient:
        raise EmailDeliveryError("EMAIL_RECIPIENT_INVALID")

    payload: dict[str, object] = {
        "from": from_email,
        "to": [recipient],
        "subject": subject,
        "text": text_body,
    }
    if html_body:
        payload["html"] = html_body

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": settings.resend_user_agent.strip() or "patroai-orkio/1.0",
    }
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key[:256]

    req = urllib_request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib_request.urlopen(
            req,
            context=ssl.create_default_context(),
            timeout=10,
        ) as response:
            raw = response.read()
            status = int(getattr(response, "status", 0) or 0)
            if status < 200 or status >= 300:
                raise EmailDeliveryError(f"RESEND_HTTP_{status}")
            try:
                parsed = json.loads(raw.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = {}
            message_id = parsed.get("id") if isinstance(parsed, dict) else None
            return str(message_id)[:255] if message_id else None
    except EmailDeliveryError:
        raise
    except Exception as exc:
        logger.warning(
            "RESEND_SEND_FAILED error_type=%s",
            exc.__class__.__name__,
        )
        raise EmailDeliveryError("RESEND_SEND_FAILED") from exc
