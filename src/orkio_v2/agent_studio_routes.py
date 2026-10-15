from __future__ import annotations

import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .auth import Principal
from .config import Settings, get_settings
from .database import get_db
from .models import AgentStudioVersion, AuditEvent
from .agents.registry import list_agents
from .services.identity import require_provisioned_superadmin
from .services.hyper_cocreator import require_allowlisted_admin_principal


router = APIRouter(prefix="/api/v2/admin/agent-studio", tags=["agent-studio"])

_SLUG_RE = re.compile(r"^[a-z][a-z0-9_-]{2,79}$")


class AgentStudioCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_slug: str = Field(min_length=3, max_length=80)
    source_kind: Literal["CUSTOM", "CANONICAL_OVERRIDE"] = "CUSTOM"
    base_agent_slug: str | None = Field(default=None, max_length=80)
    display_name: str = Field(min_length=2, max_length=160)
    canonical_name: str = Field(min_length=2, max_length=160)
    role_label: str = Field("", max_length=200)
    department: str = Field("", max_length=160)
    description: str = Field("", max_length=4000)
    system_instruction: str = Field("", max_length=50000)
    provider: str = Field("openai", min_length=1, max_length=80)
    model_name: str = Field("", max_length=160)
    temperature: Decimal = Field(Decimal("0.20"), ge=0, le=2)
    capabilities: dict = Field(default_factory=dict)
    knowledge_config: dict = Field(default_factory=dict)
    daily_budget_usd: Decimal | None = Field(default=None, ge=0)
    monthly_budget_usd: Decimal | None = Field(default=None, ge=0)

    @field_validator("agent_slug")
    @classmethod
    def validate_slug(cls, value: str) -> str:
        slug = value.strip().lower()
        if not _SLUG_RE.fullmatch(slug):
            raise ValueError("AGENT_STUDIO_SLUG_INVALID")
        return slug


class AgentStudioPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=2, max_length=160)
    canonical_name: str | None = Field(default=None, min_length=2, max_length=160)
    role_label: str | None = Field(default=None, max_length=200)
    department: str | None = Field(default=None, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    system_instruction: str | None = Field(default=None, max_length=50000)
    provider: str | None = Field(default=None, min_length=1, max_length=80)
    model_name: str | None = Field(default=None, max_length=160)
    temperature: Decimal | None = Field(default=None, ge=0, le=2)
    capabilities: dict | None = None
    knowledge_config: dict | None = None
    daily_budget_usd: Decimal | None = Field(default=None, ge=0)
    monthly_budget_usd: Decimal | None = Field(default=None, ge=0)


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_ref: str = Field(min_length=8, max_length=500)


def _require_admin(p: Principal, settings: Settings) -> Principal:
    return require_allowlisted_admin_principal(p, settings)


def _payload(row: AgentStudioVersion) -> dict:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "agent_slug": row.agent_slug,
        "base_agent_slug": row.base_agent_slug,
        "source_kind": row.source_kind,
        "version": row.version,
        "display_name": row.display_name,
        "canonical_name": row.canonical_name,
        "role_label": row.role_label,
        "department": row.department,
        "description": row.description,
        "system_instruction": row.system_instruction,
        "provider": row.provider,
        "model_name": row.model_name,
        "temperature": float(row.temperature),
        "capabilities": row.capabilities_json or {},
        "knowledge_config": row.knowledge_config_json or {},
        "daily_budget_usd": (
            float(row.daily_budget_usd) if row.daily_budget_usd is not None else None
        ),
        "monthly_budget_usd": (
            float(row.monthly_budget_usd) if row.monthly_budget_usd is not None else None
        ),
        "lifecycle_state": row.lifecycle_state,
        "runtime_enabled": bool(row.runtime_enabled),
        "review_evidence_ref": row.review_evidence_ref,
        "approval_evidence_ref": row.approval_evidence_ref,
        "created_by": row.created_by,
        "updated_by": row.updated_by,
        "approved_by": row.approved_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
    }


def _audit(
    db: Session,
    *,
    principal: Principal,
    action: str,
    row: AgentStudioVersion,
    metadata: dict | None = None,
) -> None:
    db.add(
        AuditEvent(
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action=action,
            resource_type="agent_studio_version",
            resource_id=row.id,
            outcome="SUCCESS",
            metadata_json={
                "agent_slug": row.agent_slug,
                "version": row.version,
                "state": row.lifecycle_state,
                **(metadata or {}),
            },
        )
    )


def _tenant_row(db: Session, *, tenant_id: str, row_id: str) -> AgentStudioVersion:
    row = db.scalar(
        select(AgentStudioVersion).where(
            AgentStudioVersion.id == row_id,
            AgentStudioVersion.tenant_id == tenant_id,
        )
    )
    if row is None:
        raise HTTPException(404, "AGENT_STUDIO_VERSION_NOT_FOUND")
    return row


@router.get("/llm-configuration")
def read_llm_configuration(
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
):
    """Read-only process LLM defaults; never assert the model used by a turn.

    This endpoint deliberately does not activate Agent Studio versions,
    expose provider credentials, or authorize a tenant to modify globals.
    """
    _require_admin(p, settings)
    primary = settings.llm_primary_provider
    model_by_provider = {
        "openai": settings.openai_model,
        "anthropic": settings.anthropic_model,
        "google": settings.google_model,
    }
    configured_model = (model_by_provider[primary] or "").strip()
    return {
        "primary_provider": primary,
        "configured_model": configured_model or None,
        "configuration_scope": "process",
        "configuration_source": "resolved_settings",
        "execution_model_verified": False,
        "admin_editable": False,
    }


@router.get("")
def list_agent_studio_versions(
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_admin(p, settings)
    rows = db.scalars(
        select(AgentStudioVersion)
        .where(AgentStudioVersion.tenant_id == p.tenant_id)
        .order_by(
            AgentStudioVersion.agent_slug,
            AgentStudioVersion.version.desc(),
        )
    ).all()
    return [_payload(row) for row in rows]


@router.post("")
def create_agent_studio_version(
    body: AgentStudioCreate,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_admin(p, settings)

    canonical_slugs = {agent.slug for agent in list_agents()}
    if body.source_kind == "CUSTOM":
        if body.agent_slug in canonical_slugs:
            raise HTTPException(409, "AGENT_STUDIO_CUSTOM_SLUG_CONFLICT")
        if body.base_agent_slug is not None:
            raise HTTPException(422, "AGENT_STUDIO_CUSTOM_BASE_AGENT_FORBIDDEN")
    else:
        if not body.base_agent_slug or body.base_agent_slug not in canonical_slugs:
            raise HTTPException(422, "AGENT_STUDIO_BASE_AGENT_REQUIRED")
        if body.agent_slug != body.base_agent_slug:
            raise HTTPException(422, "AGENT_STUDIO_OVERRIDE_SLUG_MISMATCH")

    existing = db.scalar(
        select(AgentStudioVersion).where(
            AgentStudioVersion.tenant_id == p.tenant_id,
            AgentStudioVersion.agent_slug == body.agent_slug,
        )
    )
    if existing is not None:
        raise HTTPException(409, "AGENT_STUDIO_AGENT_ALREADY_EXISTS")

    row = AgentStudioVersion(
        tenant_id=p.tenant_id,
        agent_slug=body.agent_slug,
        base_agent_slug=body.base_agent_slug,
        source_kind=body.source_kind,
        version=1,
        display_name=body.display_name.strip(),
        canonical_name=body.canonical_name.strip(),
        role_label=body.role_label.strip(),
        department=body.department.strip(),
        description=body.description.strip(),
        system_instruction=body.system_instruction.strip(),
        provider=body.provider.strip(),
        model_name=body.model_name.strip(),
        temperature=body.temperature,
        capabilities_json=body.capabilities,
        knowledge_config_json=body.knowledge_config,
        daily_budget_usd=body.daily_budget_usd,
        monthly_budget_usd=body.monthly_budget_usd,
        lifecycle_state="DRAFT",
        runtime_enabled=False,
        created_by=p.user_id,
        updated_by=p.user_id,
    )
    db.add(row)
    db.flush()
    _audit(db, principal=p, action="ADMIN_AGENT_STUDIO_DRAFT_CREATED", row=row)
    db.commit()
    db.refresh(row)
    return _payload(row)


@router.post("/{agent_slug}/versions")
def create_next_agent_studio_version(
    agent_slug: str,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_admin(p, settings)
    latest = db.scalar(
        select(AgentStudioVersion)
        .where(
            AgentStudioVersion.tenant_id == p.tenant_id,
            AgentStudioVersion.agent_slug == agent_slug,
        )
        .order_by(AgentStudioVersion.version.desc())
        .limit(1)
    )
    if latest is None:
        raise HTTPException(404, "AGENT_STUDIO_AGENT_NOT_FOUND")
    if latest.lifecycle_state in {"DRAFT", "REVIEW"}:
        raise HTTPException(409, "AGENT_STUDIO_OPEN_VERSION_EXISTS")

    row = AgentStudioVersion(
        tenant_id=latest.tenant_id,
        agent_slug=latest.agent_slug,
        base_agent_slug=latest.base_agent_slug,
        source_kind=latest.source_kind,
        version=latest.version + 1,
        display_name=latest.display_name,
        canonical_name=latest.canonical_name,
        role_label=latest.role_label,
        department=latest.department,
        description=latest.description,
        system_instruction=latest.system_instruction,
        provider=latest.provider,
        model_name=latest.model_name,
        temperature=latest.temperature,
        capabilities_json=dict(latest.capabilities_json or {}),
        knowledge_config_json=dict(latest.knowledge_config_json or {}),
        daily_budget_usd=latest.daily_budget_usd,
        monthly_budget_usd=latest.monthly_budget_usd,
        lifecycle_state="DRAFT",
        runtime_enabled=False,
        created_by=p.user_id,
        updated_by=p.user_id,
    )
    db.add(row)
    db.flush()
    _audit(db, principal=p, action="ADMIN_AGENT_STUDIO_VERSION_CREATED", row=row)
    db.commit()
    db.refresh(row)
    return _payload(row)


@router.patch("/versions/{row_id}")
def patch_agent_studio_draft(
    row_id: str,
    body: AgentStudioPatch,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_admin(p, settings)
    row = _tenant_row(db, tenant_id=p.tenant_id, row_id=row_id)
    if row.lifecycle_state != "DRAFT":
        raise HTTPException(409, "AGENT_STUDIO_ONLY_DRAFT_EDITABLE")

    changes = body.model_dump(exclude_unset=True)
    field_map = {
        "capabilities": "capabilities_json",
        "knowledge_config": "knowledge_config_json",
    }
    for key, value in changes.items():
        setattr(row, field_map.get(key, key), value)
    row.updated_by = p.user_id
    _audit(
        db,
        principal=p,
        action="ADMIN_AGENT_STUDIO_DRAFT_UPDATED",
        row=row,
        metadata={"fields": sorted(changes)},
    )
    db.commit()
    db.refresh(row)
    return _payload(row)


@router.post("/versions/{row_id}/review")
def submit_agent_studio_review(
    row_id: str,
    body: EvidenceRequest,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_admin(p, settings)
    row = _tenant_row(db, tenant_id=p.tenant_id, row_id=row_id)
    if row.lifecycle_state != "DRAFT":
        raise HTTPException(409, "AGENT_STUDIO_REVIEW_INVALID_STATE")
    if not row.system_instruction.strip():
        raise HTTPException(409, "AGENT_STUDIO_SYSTEM_INSTRUCTION_REQUIRED")
    if not row.model_name.strip():
        raise HTTPException(409, "AGENT_STUDIO_MODEL_REQUIRED")
    row.lifecycle_state = "REVIEW"
    row.review_evidence_ref = body.evidence_ref
    row.updated_by = p.user_id
    _audit(db, principal=p, action="ADMIN_AGENT_STUDIO_REVIEW_SUBMITTED", row=row)
    db.commit()
    db.refresh(row)
    return _payload(row)


@router.post("/versions/{row_id}/approval")
def approve_agent_studio_version(
    row_id: str,
    body: EvidenceRequest,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_admin(p, settings)
    row = _tenant_row(db, tenant_id=p.tenant_id, row_id=row_id)
    if row.lifecycle_state != "REVIEW":
        raise HTTPException(409, "AGENT_STUDIO_APPROVAL_INVALID_STATE")
    row.lifecycle_state = "APPROVED"
    row.approval_evidence_ref = body.evidence_ref
    row.approved_by = p.user_id
    row.approved_at = datetime.now(timezone.utc)
    row.updated_by = p.user_id
    _audit(db, principal=p, action="ADMIN_AGENT_STUDIO_APPROVED", row=row)
    db.commit()
    db.refresh(row)
    return _payload(row)


@router.post("/versions/{row_id}/activation")
def activate_agent_studio_version(
    row_id: str,
    body: EvidenceRequest,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_admin(p, settings)
    row = _tenant_row(db, tenant_id=p.tenant_id, row_id=row_id)
    if row.lifecycle_state != "APPROVED":
        raise HTTPException(409, "AGENT_STUDIO_ACTIVATION_INVALID_STATE")
    # Fail closed until the runtime resolver itself is tenant-aware. Never mutate
    # the process-global canonical registry from a tenant-scoped admin request.
    raise HTTPException(
        409,
        detail={
            "code": "AGENT_STUDIO_TENANT_AWARE_RUNTIME_NOT_IMPLEMENTED",
            "runtime_enabled": False,
            "evidence_ref_received": bool(body.evidence_ref),
        },
    )


@router.post("/versions/{row_id}/retire")
def retire_agent_studio_version(
    row_id: str,
    body: EvidenceRequest,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_admin(p, settings)
    row = _tenant_row(db, tenant_id=p.tenant_id, row_id=row_id)
    if row.lifecycle_state not in {"APPROVED", "SUSPENDED"}:
        raise HTTPException(409, "AGENT_STUDIO_RETIRE_INVALID_STATE")
    row.lifecycle_state = "RETIRED"
    row.runtime_enabled = False
    row.updated_by = p.user_id
    _audit(
        db,
        principal=p,
        action="ADMIN_AGENT_STUDIO_RETIRED",
        row=row,
        metadata={"evidence_ref": body.evidence_ref},
    )
    db.commit()
    db.refresh(row)
    return _payload(row)


@router.get("/versions/{row_id}/preview")
def preview_agent_studio_version(
    row_id: str,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_admin(p, settings)
    row = _tenant_row(db, tenant_id=p.tenant_id, row_id=row_id)
    return {
        "agent_slug": row.agent_slug,
        "version": row.version,
        "lifecycle_state": row.lifecycle_state,
        "runtime_enabled": False,
        "compiled_system_instruction": (
            "Você opera como um agente governado da Plataforma Efatà 777.\n"
            f"Seu nome público é {row.display_name}.\n"
            f"Cargo: {row.role_label or 'Não definido'}.\n"
            f"Departamento: {row.department or 'Não definido'}.\n\n"
            f"{row.system_instruction.strip()}"
        ).strip(),
        "provider": row.provider,
        "model": row.model_name,
        "temperature": float(row.temperature),
        "capabilities": row.capabilities_json or {},
        "knowledge_config": row.knowledge_config_json or {},
        "budget": {
            "daily_usd": (
                float(row.daily_budget_usd) if row.daily_budget_usd is not None else None
            ),
            "monthly_usd": (
                float(row.monthly_budget_usd)
                if row.monthly_budget_usd is not None
                else None
            ),
        },
        "activation": {
            "allowed": False,
            "reason_code": "AGENT_STUDIO_TENANT_AWARE_RUNTIME_NOT_IMPLEMENTED",
        },
    }
