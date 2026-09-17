from __future__ import annotations

from dataclasses import dataclass

from ..auth import Principal
from ..models import KnowledgeDocument, KnowledgeScope, KnowledgeStatus


@dataclass(frozen=True, slots=True)
class KnowledgePolicyError(RuntimeError):
    code: str
    status_code: int = 403

    def __str__(self) -> str:
        return self.code


_ADMIN_ROLES = {"admin", "orkio_admin", "owner", "superadmin", "platform_owner"}


def normalize_scope(value: str) -> str:
    scope = str(value or "").strip().upper()
    allowed = {item.value for item in KnowledgeScope}
    if scope not in allowed:
        raise KnowledgePolicyError("KNOWLEDGE_SCOPE_INVALID", 422)
    return scope


def is_tenant_admin(principal: Principal) -> bool:
    return bool(_ADMIN_ROLES.intersection(principal.roles))


def is_platform_owner(principal: Principal) -> bool:
    # Deliberately exact. `superadmin` is not sufficient unless canonical
    # provisioning also derived the dedicated `platform_owner` role.
    return "platform_owner" in principal.roles


def assert_upload_allowed(scope: str, principal: Principal) -> None:
    scope = normalize_scope(scope)
    if scope == KnowledgeScope.personal.value:
        return
    if scope == KnowledgeScope.institutional.value:
        if not is_tenant_admin(principal):
            raise KnowledgePolicyError("KNOWLEDGE_INSTITUTIONAL_ADMIN_REQUIRED")
        return
    if scope == KnowledgeScope.platform.value:
        if not is_platform_owner(principal):
            raise KnowledgePolicyError("KNOWLEDGE_PLATFORM_OWNER_REQUIRED")
        return
    raise KnowledgePolicyError("KNOWLEDGE_SCOPE_INVALID", 422)


def assert_list_allowed(scope: str, principal: Principal) -> None:
    scope = normalize_scope(scope)
    if scope == KnowledgeScope.personal.value:
        return
    if scope == KnowledgeScope.institutional.value and is_tenant_admin(principal):
        return
    if scope == KnowledgeScope.platform.value and is_platform_owner(principal):
        return
    if scope == KnowledgeScope.institutional.value:
        raise KnowledgePolicyError("KNOWLEDGE_INSTITUTIONAL_ADMIN_REQUIRED")
    raise KnowledgePolicyError("KNOWLEDGE_PLATFORM_OWNER_REQUIRED")


def assert_document_visible_for_management(
    document: KnowledgeDocument,
    principal: Principal,
) -> None:
    """Fail closed and avoid cross-tenant existence disclosure."""
    if document.scope == KnowledgeScope.platform.value:
        if not is_platform_owner(principal):
            raise KnowledgePolicyError("KNOWLEDGE_NOT_FOUND", 404)
        return

    if document.tenant_id != principal.tenant_id:
        raise KnowledgePolicyError("KNOWLEDGE_NOT_FOUND", 404)

    if document.scope == KnowledgeScope.personal.value:
        if document.owner_user_id != principal.user_id:
            raise KnowledgePolicyError("KNOWLEDGE_NOT_FOUND", 404)
        return

    if document.scope == KnowledgeScope.institutional.value:
        if not is_tenant_admin(principal):
            raise KnowledgePolicyError("KNOWLEDGE_NOT_FOUND", 404)
        return

    raise KnowledgePolicyError("KNOWLEDGE_NOT_FOUND", 404)


def assert_can_publish(document: KnowledgeDocument, principal: Principal) -> None:
    assert_document_visible_for_management(document, principal)
    if document.scope == KnowledgeScope.personal.value:
        raise KnowledgePolicyError("KNOWLEDGE_PERSONAL_PUBLISH_NOT_APPLICABLE", 409)
    if document.status != KnowledgeStatus.draft.value:
        raise KnowledgePolicyError("KNOWLEDGE_PUBLISH_REQUIRES_DRAFT", 409)


def assert_can_revoke(document: KnowledgeDocument, principal: Principal) -> None:
    assert_document_visible_for_management(document, principal)
    if document.scope == KnowledgeScope.personal.value:
        raise KnowledgePolicyError("KNOWLEDGE_PERSONAL_REVOKE_NOT_APPLICABLE", 409)
    if document.status != KnowledgeStatus.active.value:
        raise KnowledgePolicyError("KNOWLEDGE_REVOKE_REQUIRES_ACTIVE", 409)


def assert_can_supersede(document: KnowledgeDocument, principal: Principal) -> None:
    assert_document_visible_for_management(document, principal)
    if document.scope == KnowledgeScope.personal.value:
        raise KnowledgePolicyError("KNOWLEDGE_PERSONAL_SUPERSEDE_NOT_APPLICABLE", 409)
    if document.status != KnowledgeStatus.active.value:
        raise KnowledgePolicyError("KNOWLEDGE_SUPERSEDE_REQUIRES_ACTIVE", 409)


def assert_can_delete(document: KnowledgeDocument, principal: Principal) -> None:
    assert_document_visible_for_management(document, principal)
    if document.scope == KnowledgeScope.personal.value:
        return
    if document.status == KnowledgeStatus.draft.value:
        return
    raise KnowledgePolicyError("KNOWLEDGE_DELETE_REQUIRES_PERSONAL_OR_DRAFT", 409)
