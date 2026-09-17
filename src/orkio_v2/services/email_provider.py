from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..config import Settings
from .email_delivery import EmailDeliveryError, send_resend_email


DELIVERY_PENDING = "PENDING"
DELIVERY_ACCEPTED_BY_PROVIDER = "ACCEPTED_BY_PROVIDER"
DELIVERY_FAILED = "DELIVERY_FAILED"


class EmailProviderError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class DeliveryResult:
    status: str
    provider_message_id: str | None = None
    error_code: str | None = None


class EmailProvider(Protocol):
    provider_name: str

    def send_platform_invitation(
        self,
        *,
        to_email: str,
        activation_url: str,
        expires_hours: int,
        idempotency_key: str,
    ) -> DeliveryResult:
        ...


class ResendEmailProvider:
    provider_name = "resend"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def send_platform_invitation(
        self,
        *,
        to_email: str,
        activation_url: str,
        expires_hours: int,
        idempotency_key: str,
    ) -> DeliveryResult:
        subject = "Seu acesso à EFATÀ 777"
        text_body = (
            "Você recebeu um convite para acessar a EFATÀ 777.\n\n"
            f"Ative seu acesso: {activation_url}\n\n"
            f"Este convite expira em até {expires_hours} hora(s) e pode ser usado uma única vez.\n"
            "Se você não esperava este convite, ignore esta mensagem."
        )
        html_body = (
            "<p>Você recebeu um convite para acessar a <strong>EFATÀ 777</strong>.</p>"
            f'<p><a href="{activation_url}">Ativar acesso</a></p>'
            f"<p>Este convite expira em até {expires_hours} hora(s) e pode ser usado uma única vez.</p>"
            "<p>Se você não esperava este convite, ignore esta mensagem.</p>"
        )
        try:
            message_id = send_resend_email(
                settings=self.settings,
                to_email=to_email,
                subject=subject,
                text_body=text_body,
                html_body=html_body,
                idempotency_key=idempotency_key,
            )
        except EmailDeliveryError as exc:
            return DeliveryResult(status=DELIVERY_FAILED, error_code=str(exc))
        return DeliveryResult(
            status=DELIVERY_ACCEPTED_BY_PROVIDER,
            provider_message_id=message_id,
        )


def build_email_provider(settings: Settings) -> EmailProvider:
    """Build a fail-closed provider.

    A configured provider can prove only API acceptance. It does not prove
    mailbox delivery, open, or click.
    """
    if not settings.resend_api_key.strip():
        raise EmailProviderError("EMAIL_PROVIDER_NOT_CONFIGURED")
    if not settings.resend_from.strip() or "@" not in settings.resend_from:
        raise EmailProviderError("EMAIL_PROVIDER_SENDER_INVALID")
    return ResendEmailProvider(settings)
