"""Normalização fail-closed da identidade OIDC.

Nenhum valor de claim é registrado por este módulo. A função normaliza
identidade e roles do provedor, preservando o vínculo role→tenant quando
o provedor entrega um mapping no formato do ZITADEL.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


class OIDCIdentityMappingError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class NormalizedOIDCIdentity:
    user_id: str
    tenant_id: str
    roles: tuple[str, ...]
    email: str | None
    external_subject: str


def _required_scalar(data: Mapping[str, object], key: str, code: str) -> str:
    value = data.get(key)
    if value is None:
        raise OIDCIdentityMappingError(code)
    text = str(value).strip()
    if not text:
        raise OIDCIdentityMappingError(code)
    return text


def _normalize_roles(value: object, tenant_id: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        role = value.strip()
        return (role,) if role else ()
    if isinstance(value, Mapping):
        accepted: list[str] = []
        for raw_role, raw_binding in value.items():
            role = str(raw_role).strip()
            if not role:
                continue
            bound = False
            if isinstance(raw_binding, Mapping):
                bound = tenant_id in {str(key) for key in raw_binding.keys()}
            elif isinstance(raw_binding, (list, tuple, set, frozenset)):
                bound = tenant_id in {str(item) for item in raw_binding}
            elif raw_binding is not None:
                bound = str(raw_binding) == tenant_id
            if bound:
                accepted.append(role)
        return tuple(sorted(set(accepted)))
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(sorted({str(item).strip() for item in value if str(item).strip()}))
    raise OIDCIdentityMappingError("ROLE_CLAIM_INVALID")


def normalize_oidc_identity(
    data: Mapping[str, object],
    *,
    user_claim: str,
    tenant_claim: str,
    roles_claim: str,
) -> NormalizedOIDCIdentity:
    user_id = _required_scalar(data, user_claim, "USER_CLAIM_MISSING")
    tenant_id = _required_scalar(data, tenant_claim, "TENANT_CLAIM_MISSING")
    external_subject = _required_scalar(data, "sub", "SUBJECT_CLAIM_MISSING")
    roles = _normalize_roles(data.get(roles_claim), tenant_id)
    email_value = data.get("email")
    email = str(email_value).strip() if email_value else None
    return NormalizedOIDCIdentity(
        user_id=user_id,
        tenant_id=tenant_id,
        roles=roles,
        email=email,
        external_subject=external_subject,
    )


def safe_oidc_diagnostics(
    data: Mapping[str, object],
    *,
    user_claim: str,
    tenant_claim: str,
    roles_claim: str,
) -> dict[str, object]:
    """Retorna somente presença/tipo; nunca valores de identidade."""
    role_value = data.get(roles_claim)
    if role_value is None:
        role_type = "missing"
    elif isinstance(role_value, str):
        role_type = "string"
    elif isinstance(role_value, Mapping):
        role_type = "mapping"
    elif isinstance(role_value, (list, tuple, set, frozenset)):
        role_type = "sequence"
    else:
        role_type = "invalid"
    return {
        "user_claim_present": bool(data.get(user_claim)),
        "tenant_claim_present": bool(data.get(tenant_claim)),
        "roles_claim_present": roles_claim in data,
        "roles_claim_type": role_type,
        "subject_claim_present": bool(data.get("sub")),
        "resourceowner_id_claim_present": bool(
            data.get("urn:zitadel:iam:user:resourceowner:id")
        ),
        "project_roles_claim_present": (
            "urn:zitadel:iam:org:project:roles" in data
        ),
    }
