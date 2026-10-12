import asyncio, hashlib, json, logging, threading
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select, text, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from .auth import Principal, require_principal
from .config import Settings, get_settings
from .database import Base, get_db, engine
from .models import *
from .schemas import *
from .services.invitations import create_invitation, accept_invitation
from .services.identity import (
    require_provisioned_principal,
    require_provisioned_admin,
    require_provisioned_superadmin,
    require_known_principal,
    assert_provisioned,
)
from .services.hyper_cocreator import (
    AccessGateError,
    complete_onboarding,
    hyper_cocreator_profile_message,
    hyper_cocreator_system_message,
    is_allowlisted_admin,
    profile_for,
    require_allowlisted_admin_principal,
    update_profile_name,
    validate_access_code,
)
from .services import llm
from .services.github_agent_tools import prepare_github_tool_history
from .services.document_context import build_document_context, document_context_message
from .services.artifact_context import artifact_context_message
from .services.platform_knowledge import system_capability_guard_message
from .services.knowledge_retrieval import knowledge_context_messages
from .services.attachment_service import AttachmentIdentityConflict, persist_attachment
from .services.unified_document_intake import (
    UnifiedDocumentIntakeError,
    ingest_large_file,
    ingest_large_paste,
)
from .services.blob_storage import BlobStorageError, build_blob_storage
from .billing import repository as billing_repository
from .services.voice_binding import VoiceProfile
from .services.text_to_speech import TextToSpeechError, synthesize_speech
from .agents.registry import AgentNotFound, list_agents
from .services.execution_router import resolve_direct_target_decision
from .services.target_resolver import TargetAmbiguous, TargetNotFound
from .services.direct_runtime import (
    build_turn as build_direct_turn,
    envelope_payload,
    persist_agent_response,
)
from .services.thread_access_policy import (
    ThreadAccessPolicyError,
    require_thread_access,
    visible_messages,
)
from .services.conversation_history_policy import (
    DIRECT_HISTORY_POLICY_VERSION,
    project_direct_history,
)
from .runtime.contracts import RuntimeChannel
from .runtime.events import RuntimeEvent, RuntimeEventType, validate_runtime_sequence
from .services.execution_correlation import ExecutionCorrelation
from .services.audit_observability import ExecutionObserver
from .services.agent_availability import availability_for, readiness_probe_for_id
from .services.artifact_generation import (
    ArtifactGenerationError,
    ArtifactStorageError,
    artifact_capability_manifest,
    artifact_generation_system_message,
    artifact_payload,
    default_filename,
    detect_artifact_intent,
    persist_validated_artifact,
    render_and_validate,
)
from .services.github_integration import (
    GitHubIntegrationError,
    allowed_repositories,
    github_context_messages,
    repository_snapshot,
)
from .services.capability_plane import (
    capability_manifest_message,
    privileged_roles,
    runtime_capability_messages,
)
from .services.capability_policy import CapabilityPolicy, CapabilityPolicyError
from .services.team_runtime import list_team_definitions, team_definition_payload
from .services.internal_consultation import (
    InternalConsultationError,
    build_internal_consultation_context,
    internal_contribution_messages,
)
from .services.python_tool import PythonToolError
from .services.python_runtime.contracts import PythonRuntimeContext, PythonRuntimeError
from .services.python_runtime.gateway import execute_python_runtime
from .services.external_read_tool import ExternalReadError, read_external_url
from .services.ao01_audit_trace import emit_audit_trace
from .services.audit_invocation_directive import looks_like_audit_directive
from .services.audit_natural_binding import (
    NaturalAuditBinding,
    resolve_natural_audit_binding,
)
from .services.audit_invocation_rate_limit import AuditDirectiveAbuseLimiter
from .services.audit_invocation_service import (
    AuditInvocationError,
    AuditInvocationOutcome,
    GovernedAuditInvocationService,
)

router=APIRouter(prefix="/api/v2")
artifact_gate_logger=logging.getLogger("orkio.artifact_gate")
internal_consultation_logger=logging.getLogger("orkio.internal_consultation")
llm_runtime_logger=logging.getLogger("orkio.llm_runtime")
history_policy_logger=logging.getLogger("orkio.history_policy")


def _audit_trace_turn(
    stage: str,
    *,
    turn,
    settings: Settings,
    capability_id: str | None = None,
    operation: str | None = None,
    audit_execution_id: str | None = None,
    status: str | None = None,
    error_code: str | None = None,
) -> None:
    emit_audit_trace(
        stage,
        trace_id=turn.execution_id,
        request_id=turn.request_id,
        execution_id=turn.execution_id,
        audit_execution_id=audit_execution_id,
        thread_id=turn.thread_id,
        tenant_id=turn.tenant_id,
        requested_agent=turn.requested_target,
        resolved_agent=turn.resolved_agent_id,
        turn_owner=turn.turn_owner_agent_id,
        route_family=turn.route_family.value,
        channel=turn.channel.value,
        capability_id=capability_id,
        operation=operation,
        deployment_id=(
            getattr(settings, "railway_deployment_id", None)
            or getattr(settings, "release_sha", None)
            or "unknown"
        ),
        build_sha=str(getattr(settings, "release_sha", "unknown") or "unknown"),
        status=status,
        error_code=error_code,
    )


_audit_directive_abuse_limiters: dict[int, AuditDirectiveAbuseLimiter] = {}
_audit_directive_abuse_limiters_lock = threading.Lock()


def _audit_session_factory(db: Session):
    return sessionmaker(bind=db.get_bind(), expire_on_commit=False)


def _audit_directive_abuse_limiter(policy: CapabilityPolicy) -> AuditDirectiveAbuseLimiter:
    limit = int(policy.audit_directive_user_rate_limit)
    with _audit_directive_abuse_limiters_lock:
        limiter = _audit_directive_abuse_limiters.get(limit)
        if limiter is None:
            limiter = AuditDirectiveAbuseLimiter(
                window_seconds=60,
                per_user_limit=limit,
            )
            _audit_directive_abuse_limiters[limit] = limiter
        return limiter


def _audit_invocation_service(db: Session, settings: Settings) -> GovernedAuditInvocationService:
    policy = CapabilityPolicy.from_env()
    return GovernedAuditInvocationService(
        session_factory=_audit_session_factory(db),
        settings=settings,
        project_root=Path(__file__).resolve().parents[2],
        policy=policy,
        directive_abuse_limiter=_audit_directive_abuse_limiter(policy),
    )


def _audit_error_detail(exc: AuditInvocationError) -> dict[str, object]:
    detail: dict[str, object] = {"code": exc.code}
    if exc.audit_reference is not None:
        detail["audit"] = exc.audit_reference
    return detail


@router.post("/access/validate")
def validate_platform_access(
    payload: AccessCodeValidateRequest,
    settings: Settings = Depends(get_settings),
):
    """Exchange a private access code for a short-lived signed onboarding grant.

    Raw codes are never returned or persisted here. Production configuration stores
    only SHA-256 digests via PLATFORM_ACCESS_GATE_CODE_HASHES.
    """
    try:
        grant = validate_access_code(settings, payload.code)
    except AccessGateError as exc:
        status = 503 if exc.code == "ACCESS_GATE_DISABLED" else 403
        raise HTTPException(status, exc.code) from exc
    return {
        "grant": grant.token,
        "expires_at": grant.expires_at,
        "onboarding_required": True,
    }


@router.post("/onboarding/complete")
def complete_hyper_cocreator_onboarding(
    payload: HyperCocreatorOnboardingComplete,
    p: Principal = Depends(require_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """Provision the authenticated OIDC identity and persist the UX profile.

    Passwords are owned by the configured identity provider; this API never receives
    or stores application passwords.
    """
    try:
        profile = complete_onboarding(
            db,
            settings=settings,
            principal=p,
            grant_token=payload.grant,
            co_creator_name=payload.co_creator_name,
            onboarding_goal=payload.onboarding_goal,
        )
    except AccessGateError as exc:
        status = 409 if exc.code in {
            "ACCESS_GRANT_ALREADY_USED",
            "ACCESS_IDENTITY_CONFLICT",
            "ACCESS_ONBOARDING_CONFLICT",
        } else 403
        raise HTTPException(status, exc.code) from exc
    return {
        "status": "provisioned",
        "user_id": p.user_id,
        "tenant_id": p.tenant_id,
        "co_creator_name": profile.co_creator_name,
        "onboarding_goal": profile.onboarding_goal,
    }


@router.get("/me")
def me(
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    profile = profile_for(db, tenant_id=p.tenant_id, user_id=p.user_id)
    current_user = db.get(User, p.user_id)
    return {
        "user_id": p.user_id,
        "tenant_id": p.tenant_id,
        "email": p.email,
        "display_name": current_user.display_name if current_user else None,
        "roles": list(p.roles),
        "admin_access": is_allowlisted_admin(p, settings),
        "co_creator_name": (
            profile.co_creator_name if profile else "Co-Criador"
        ),
        "onboarding_goal": profile.onboarding_goal if profile else None,
    }


@router.patch("/me/co-creator")
def rename_hyper_cocreator(
    payload: HyperCocreatorProfileUpdate,
    p: Principal = Depends(require_provisioned_principal),
    db: Session = Depends(get_db),
):
    profile = update_profile_name(
        db,
        principal=p,
        co_creator_name=payload.co_creator_name,
    )
    return {
        "status": "updated",
        "co_creator_name": profile.co_creator_name,
        "onboarding_goal": profile.onboarding_goal,
    }


@router.get("/admin/overview")
def admin_overview(
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    require_allowlisted_admin_principal(p, settings)
    return {
        "tenant_id": p.tenant_id,
        "users": int(
            db.scalar(
                select(func.count(Membership.id)).where(
                    Membership.tenant_id == p.tenant_id,
                    Membership.active.is_(True),
                )
            )
            or 0
        ),
        "threads": int(
            db.scalar(
                select(func.count(Thread.id)).where(
                    Thread.tenant_id == p.tenant_id
                )
            )
            or 0
        ),
        "messages": int(
            db.scalar(
                select(func.count(Message.id)).where(
                    Message.tenant_id == p.tenant_id
                )
            )
            or 0
        ),
        "co_creator_profiles": int(
            db.scalar(
                select(func.count(UserExperienceProfile.id)).where(
                    UserExperienceProfile.tenant_id == p.tenant_id
                )
            )
            or 0
        ),
        "environment": settings.environment,
        "release_sha": settings.release_sha,
    }

def _resolve_audit_request(
    message: str,
    *,
    resolved_agent_id: str,
) -> tuple[bool, str | None, NaturalAuditBinding | None]:
    if looks_like_audit_directive(message):
        return True, message, None
    natural = resolve_natural_audit_binding(
        message,
        resolved_agent_id=resolved_agent_id,
    )
    if natural is None:
        return False, None, None
    return True, natural.directive_message, natural


def _natural_audit_http_error(binding: NaturalAuditBinding) -> HTTPException:
    code = binding.error_code or "CAPABILITY_UNAVAILABLE"
    status = 501 if code == "CAPABILITY_UNAVAILABLE" else 400
    detail: dict[str, object] = {
        "code": code,
        "audit_intent": binding.intent,
        "evidence_status": "NOT_PROVEN",
    }
    if binding.required_capability_id:
        detail["required_capability_id"] = binding.required_capability_id
    return HTTPException(status, detail=detail)


def _require_console_superadmin(p: Principal, settings: Settings) -> Principal:
    return require_allowlisted_admin_principal(p, settings)


@router.get("/admin/usage-costs")
def admin_usage_costs(
    days: int = Query(30, ge=1, le=90),
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    events = db.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.tenant_id == p.tenant_id,
            AuditEvent.action == "message_tts_request",
            AuditEvent.created_at >= cutoff,
        )
        .order_by(AuditEvent.created_at.desc())
    ).all()

    requests = 0
    provider_syntheses = 0
    cache_hits = 0
    idempotency_replays = 0
    chars_requested = 0
    chars_provider = 0
    by_agent: dict[str, dict[str, int]] = {}

    for event in events:
        if event.outcome != "success":
            continue
        metadata = event.metadata_json or {}
        requests += 1
        chars = int(metadata.get("chars") or 0)
        chars_requested += chars
        cache_hit = bool(metadata.get("cache_hit"))
        replay = bool(metadata.get("idempotency_replay"))
        if cache_hit:
            cache_hits += 1
        if replay:
            idempotency_replays += 1
        if not cache_hit and not replay:
            provider_syntheses += 1
            chars_provider += chars
        agent_id = str(metadata.get("agent_id") or "unknown")
        bucket = by_agent.setdefault(
            agent_id,
            {"requests": 0, "provider_syntheses": 0, "chars": 0},
        )
        bucket["requests"] += 1
        bucket["chars"] += chars
        if not cache_hit and not replay:
            bucket["provider_syntheses"] += 1

    rate = float(settings.tts_cost_per_1m_chars_usd)
    estimated = round((chars_provider / 1_000_000.0) * rate, 6) if rate > 0 else None
    billing = billing_repository.admin_summary(db, tenant_id=p.tenant_id)

    return {
        "tenant_id": p.tenant_id,
        "window_days": days,
        "tts": {
            "requests": requests,
            "provider_syntheses": provider_syntheses,
            "cache_hits": cache_hits,
            "idempotency_replays": idempotency_replays,
            "chars_requested": chars_requested,
            "chars_provider_synthesized": chars_provider,
            "cost_rate_configured": rate > 0,
            "cost_per_1m_chars_usd": rate if rate > 0 else None,
            "estimated_provider_cost_usd": estimated,
            "by_agent": by_agent,
        },
        "billing": {
            key: float(value) if hasattr(value, "as_tuple") else value
            for key, value in billing.items()
        },
        "llm_usage": {
            "status": "NOT_METERED",
            "reason_code": "LLM_TOKEN_LEDGER_NOT_IMPLEMENTED",
        },
    }


@router.get("/admin/users")
def admin_users(
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    rows = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.tenant_id == p.tenant_id)
        .order_by(func.lower(User.email))
    ).all()
    return [
        {
            "user_id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "role": membership.role,
            "active": membership.active,
            "email_verified": user.email_verified_at is not None,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }
        for membership, user in rows
    ]


@router.get("/admin/agents")
def admin_agents(
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
):
    _require_console_superadmin(p, settings)
    return [
        {
            "slug": agent.slug,
            "canonical_name": agent.canonical_name,
            "display_name": agent.display_name,
            "role_code": agent.role_code,
            "role_label": agent.role_label,
            "organizational_level": agent.organizational_level,
            "department": agent.department,
            "founder_direct_access": agent.founder_direct_access,
            "target_kind": agent.target_kind.value,
            "availability": availability_for(agent, settings).to_dict(),
        }
        for agent in list_agents()
    ]


def _admin_voice_catalog_payload(row: VoiceCatalogEntry) -> dict:
    return {
        "id": row.id,
        "provider_key": row.provider_key,
        "provider_voice_id": row.provider_voice_id,
        "display_name": row.display_name,
        "provider_model": row.provider_model,
        "source_type": row.source_type,
        "license_label": row.license_label,
        "cost_class": row.cost_class,
        "provenance_url": row.provenance_url,
        "catalog_version": row.catalog_version,
        "supported_locales": row.supported_locales,
        "delivery_modes": row.delivery_modes,
        "curation_status": row.curation_status,
        "active": row.active,
    }


@router.get("/admin/voice-catalog")
def admin_voice_catalog(
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    rows = db.scalars(
        select(VoiceCatalogEntry).order_by(
            VoiceCatalogEntry.provider_key,
            VoiceCatalogEntry.display_name,
        )
    ).all()
    return [_admin_voice_catalog_payload(row) for row in rows]


@router.post("/admin/voice-catalog")
def admin_create_voice_catalog_entry(
    body: AdminVoiceCatalogCreate,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    duplicate = db.scalar(
        select(VoiceCatalogEntry).where(
            VoiceCatalogEntry.provider_key == body.provider_key,
            VoiceCatalogEntry.provider_voice_id == body.provider_voice_id,
        )
    )
    if duplicate is not None:
        raise HTTPException(409, "VOICE_CATALOG_ENTRY_EXISTS")

    row = VoiceCatalogEntry(
        provider_key=body.provider_key,
        provider_voice_id=body.provider_voice_id.strip(),
        display_name=body.display_name.strip(),
        provider_model=body.provider_model.strip(),
        source_type=body.source_type,
        license_label=body.license_label.strip(),
        cost_class=body.cost_class.strip(),
        provenance_url=(body.provenance_url or "").strip() or None,
        catalog_version=body.catalog_version.strip(),
        supported_locales=list(dict.fromkeys(body.supported_locales)),
        delivery_modes=list(dict.fromkeys(body.delivery_modes)),
        curation_status="REVIEW_REQUIRED",
        active=True,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "VOICE_CATALOG_ENTRY_EXISTS") from exc
    db.add(
        AuditEvent(
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            action="ADMIN_VOICE_CATALOG_CREATED",
            resource_type="voice_catalog_entry",
            resource_id=row.id,
            outcome="SUCCESS",
            metadata_json={
                "provider_key": row.provider_key,
                "provider_voice_id": row.provider_voice_id,
                "curation_status": row.curation_status,
            },
        )
    )
    db.commit()
    db.refresh(row)
    return _admin_voice_catalog_payload(row)


@router.post("/admin/voice-catalog/{voice_id}/curation")
def admin_curate_voice_catalog_entry(
    voice_id: str,
    body: AdminVoiceCatalogCurationUpdate,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    row = db.get(VoiceCatalogEntry, voice_id)
    if row is None:
        raise HTTPException(404, "VOICE_CATALOG_ENTRY_NOT_FOUND")
    if not row.active:
        raise HTTPException(409, "VOICE_CATALOG_ENTRY_INACTIVE")
    row.curation_status = body.curation_status
    db.add(
        AuditEvent(
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            action="ADMIN_VOICE_CATALOG_CURATED",
            resource_type="voice_catalog_entry",
            resource_id=row.id,
            outcome="SUCCESS",
            metadata_json={
                "curation_status": body.curation_status,
                "evidence_ref": body.evidence_ref,
            },
        )
    )
    db.commit()
    db.refresh(row)
    return _admin_voice_catalog_payload(row)


@router.post("/admin/voice-catalog/{voice_id}/deactivation")
def admin_deactivate_voice_catalog_entry(
    voice_id: str,
    body: AdminVoiceCatalogDeactivateRequest,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    row = db.get(VoiceCatalogEntry, voice_id)
    if row is None:
        raise HTTPException(404, "VOICE_CATALOG_ENTRY_NOT_FOUND")
    in_use = db.scalar(
        select(AgentVoiceAssignment).where(
            AgentVoiceAssignment.voice_catalog_id == row.id,
            AgentVoiceAssignment.active.is_(True),
        )
    )
    if in_use is not None:
        raise HTTPException(409, "VOICE_CATALOG_ENTRY_IN_USE")
    row.active = False
    db.add(
        AuditEvent(
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            action="ADMIN_VOICE_CATALOG_DEACTIVATED",
            resource_type="voice_catalog_entry",
            resource_id=row.id,
            outcome="SUCCESS",
            metadata_json={"evidence_ref": body.evidence_ref},
        )
    )
    db.commit()
    db.refresh(row)
    return _admin_voice_catalog_payload(row)


@router.post("/admin/voice-catalog/{voice_id}/activation")
def admin_activate_voice_catalog_entry(
    voice_id: str,
    body: AdminVoiceCatalogDeactivateRequest,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """Reactivate a previously deactivated catalog entry.

    Activation only restores the catalog entry's availability. It does not
    create or reactivate any agent assignment; assignment validation and
    activation remain separate governed gates.
    """
    _require_console_superadmin(p, settings)
    row = db.get(VoiceCatalogEntry, voice_id)
    if row is None:
        raise HTTPException(404, "VOICE_CATALOG_ENTRY_NOT_FOUND")
    if row.active:
        return _admin_voice_catalog_payload(row)
    row.active = True
    db.add(
        AuditEvent(
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            action="ADMIN_VOICE_CATALOG_ACTIVATED",
            resource_type="voice_catalog_entry",
            resource_id=row.id,
            outcome="SUCCESS",
            metadata_json={"evidence_ref": body.evidence_ref},
        )
    )
    db.commit()
    db.refresh(row)
    return _admin_voice_catalog_payload(row)


@router.post("/admin/voice-catalog/{voice_id}/preview")
async def admin_preview_voice_catalog_entry(
    voice_id: str,
    body: AdminVoiceCatalogPreviewRequest,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    row = db.get(VoiceCatalogEntry, voice_id)
    if row is None:
        raise HTTPException(404, "VOICE_CATALOG_ENTRY_NOT_FOUND")
    if not row.active:
        raise HTTPException(409, "VOICE_CATALOG_ENTRY_INACTIVE")
    if body.locale not in set(row.supported_locales or []):
        raise HTTPException(422, "VOICE_LOCALE_NOT_SUPPORTED")
    if "MESSAGE_PLAYBACK" not in set(row.delivery_modes or []):
        raise HTTPException(422, "VOICE_DELIVERY_MODE_NOT_SUPPORTED")
    profile = VoiceProfile(
        agent_id="admin-preview",
        binding_id=f"catalog-preview:{row.id}",
        binding_version=row.catalog_version,
        locale=body.locale,
        provider=row.provider_key,
        voice_id=row.provider_voice_id,
        model=row.provider_model,
        source_type=row.source_type,
        delivery_mode="MESSAGE_PLAYBACK",
        provider_profile_version=row.catalog_version,
    )
    try:
        audio = await synthesize_speech(
            settings,
            profile,
            body.text,
            request_id=f"admin-voice-preview:{row.id}",
        )
    except TextToSpeechError as exc:
        status = 503 if exc.code in {"TTS_DISABLED", "TTS_PROVIDER_UNAVAILABLE"} else 422
        raise HTTPException(status, exc.code) from exc

    db.add(
        AuditEvent(
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            action="ADMIN_VOICE_CATALOG_PREVIEWED",
            resource_type="voice_catalog_entry",
            resource_id=row.id,
            outcome="SUCCESS",
            metadata_json={
                "locale": body.locale,
                "chars": len(body.text),
            },
        )
    )
    db.commit()
    return Response(
        content=audio,
        media_type="audio/mpeg",
        headers={
            "X-Efata-Voice-Catalog-Id": row.id,
            "X-Efata-Voice-Provider": row.provider_key,
        },
    )


@router.get("/admin/agent-voice-assignments")
def admin_agent_voice_assignments(
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    rows = db.execute(
        select(AgentVoiceAssignment, VoiceCatalogEntry)
        .join(VoiceCatalogEntry, VoiceCatalogEntry.id == AgentVoiceAssignment.voice_catalog_id)
        .where(AgentVoiceAssignment.tenant_id == p.tenant_id)
        .order_by(AgentVoiceAssignment.agent_slug, AgentVoiceAssignment.version.desc())
    ).all()
    return [{
        "id": assignment.id, "agent_slug": assignment.agent_slug, "locale": assignment.locale,
        "voice_catalog_id": voice.id, "voice_display_name": voice.display_name,
        "provider_key": voice.provider_key, "assignment_state": assignment.assignment_state,
        "validation_status": assignment.validation_status, "active": assignment.active,
        "presentation_label": assignment.presentation_label, "timbre_label": assignment.timbre_label,
        "energy_label": assignment.energy_label, "version": assignment.version,
    } for assignment, voice in rows]


@router.put("/admin/agents/{agent_slug}/voice-assignment")
def admin_upsert_agent_voice_assignment(
    agent_slug: str,
    body: AdminVoiceAssignmentUpsert,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    if not any(agent.slug == agent_slug for agent in list_agents()):
        raise HTTPException(404, "AGENT_NOT_FOUND")
    voice = db.get(VoiceCatalogEntry, body.voice_catalog_id)
    if not voice or not voice.active or voice.curation_status != "APPROVED":
        raise HTTPException(409, "VOICE_NOT_ELIGIBLE")
    duplicate = db.scalar(select(AgentVoiceAssignment).where(
        AgentVoiceAssignment.tenant_id == p.tenant_id,
        AgentVoiceAssignment.voice_catalog_id == voice.id,
        AgentVoiceAssignment.active.is_(True),
        AgentVoiceAssignment.agent_slug != agent_slug,
    ))
    if duplicate:
        raise HTTPException(409, "VOICE_ALREADY_ASSIGNED")
    prior = db.scalar(select(AgentVoiceAssignment).where(
        AgentVoiceAssignment.tenant_id == p.tenant_id,
        AgentVoiceAssignment.agent_slug == agent_slug,
        AgentVoiceAssignment.locale == body.locale,
        AgentVoiceAssignment.active.is_(True),
    ))
    next_version = 1
    if prior:
        prior.active = False
        prior.assignment_state = "DISABLED"
        prior.updated_by = p.user_id
        next_version = prior.version + 1
    assignment = AgentVoiceAssignment(
        tenant_id=p.tenant_id, agent_slug=agent_slug, voice_catalog_id=voice.id,
        locale=body.locale, delivery_modes=body.delivery_modes,
        presentation_label=body.presentation_label, timbre_label=body.timbre_label,
        energy_label=body.energy_label, assignment_state="DRAFT",
        validation_status="UNVALIDATED", active=True, version=next_version,
        created_by=p.user_id, updated_by=p.user_id,
    )
    db.add(assignment)
    db.flush()
    db.add(AuditEvent(tenant_id=p.tenant_id, actor_id=p.user_id,
        action="ADMIN_AGENT_VOICE_ASSIGNMENT_DRAFT", resource_type="agent_voice_assignment",
        resource_id=assignment.id, outcome="SUCCESS", metadata_json={
            "agent_slug": agent_slug, "voice_catalog_id": voice.id,
            "assignment_state": "DRAFT", "validation_status": "UNVALIDATED"}))
    db.commit()
    return {"id": assignment.id, "agent_slug": assignment.agent_slug,
        "voice_catalog_id": voice.id, "voice_display_name": voice.display_name,
        "provider_key": voice.provider_key, "locale": assignment.locale,
        "delivery_modes": assignment.delivery_modes, "presentation_label": assignment.presentation_label,
        "timbre_label": assignment.timbre_label, "energy_label": assignment.energy_label,
        "assignment_state": assignment.assignment_state, "validation_status": assignment.validation_status,
        "active": assignment.active, "version": assignment.version}


def _admin_voice_assignment_payload(
    assignment: AgentVoiceAssignment,
    voice: VoiceCatalogEntry,
) -> dict:
    return {
        "id": assignment.id,
        "agent_slug": assignment.agent_slug,
        "voice_catalog_id": voice.id,
        "voice_display_name": voice.display_name,
        "provider_key": voice.provider_key,
        "locale": assignment.locale,
        "delivery_modes": assignment.delivery_modes,
        "presentation_label": assignment.presentation_label,
        "timbre_label": assignment.timbre_label,
        "energy_label": assignment.energy_label,
        "assignment_state": assignment.assignment_state,
        "validation_status": assignment.validation_status,
        "active": assignment.active,
        "version": assignment.version,
    }


def _tenant_voice_assignment_or_404(
    db: Session,
    *,
    tenant_id: str,
    assignment_id: str,
) -> AgentVoiceAssignment:
    assignment = db.scalar(
        select(AgentVoiceAssignment).where(
            AgentVoiceAssignment.id == assignment_id,
            AgentVoiceAssignment.tenant_id == tenant_id,
        )
    )
    if assignment is None:
        raise HTTPException(404, "VOICE_ASSIGNMENT_NOT_FOUND")
    return assignment


@router.post("/admin/agent-voice-assignments/{assignment_id}/validation")
def admin_validate_agent_voice_assignment(
    assignment_id: str,
    body: AdminVoiceAssignmentValidationUpdate,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    assignment = _tenant_voice_assignment_or_404(
        db,
        tenant_id=p.tenant_id,
        assignment_id=assignment_id,
    )
    if not assignment.active or assignment.assignment_state != "DRAFT":
        raise HTTPException(409, "VOICE_ASSIGNMENT_NOT_DRAFT")

    voice = db.get(VoiceCatalogEntry, assignment.voice_catalog_id)
    if voice is None:
        raise HTTPException(409, "VOICE_CATALOG_ENTRY_NOT_FOUND")

    if body.validation_status == "VALIDATED":
        if (
            not voice.active
            or voice.curation_status != "APPROVED"
            or assignment.locale not in set(voice.supported_locales or [])
            or not set(assignment.delivery_modes or []).issubset(
                set(voice.delivery_modes or [])
            )
        ):
            raise HTTPException(409, "VOICE_NOT_ELIGIBLE")

    assignment.validation_status = body.validation_status
    assignment.updated_by = p.user_id
    db.add(
        AuditEvent(
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            action="ADMIN_AGENT_VOICE_ASSIGNMENT_VALIDATION",
            resource_type="agent_voice_assignment",
            resource_id=assignment.id,
            outcome="SUCCESS",
            metadata_json={
                "agent_slug": assignment.agent_slug,
                "voice_catalog_id": voice.id,
                "validation_status": assignment.validation_status,
                "evidence_ref": body.evidence_ref,
            },
        )
    )
    db.commit()
    return _admin_voice_assignment_payload(assignment, voice)


@router.post("/admin/agent-voice-assignments/{assignment_id}/activation")
def admin_activate_agent_voice_assignment(
    assignment_id: str,
    body: AdminVoiceAssignmentActivationRequest,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    assignment = _tenant_voice_assignment_or_404(
        db,
        tenant_id=p.tenant_id,
        assignment_id=assignment_id,
    )
    if not assignment.active or assignment.assignment_state != "DRAFT":
        raise HTTPException(409, "VOICE_ASSIGNMENT_NOT_DRAFT")
    if assignment.validation_status != "VALIDATED":
        raise HTTPException(409, "VOICE_ASSIGNMENT_NOT_VALIDATED")

    voice = db.get(VoiceCatalogEntry, assignment.voice_catalog_id)
    if (
        voice is None
        or not voice.active
        or voice.curation_status != "APPROVED"
        or assignment.locale not in set(voice.supported_locales or [])
        or not set(assignment.delivery_modes or []).issubset(
            set(voice.delivery_modes or [])
        )
    ):
        raise HTTPException(409, "VOICE_NOT_ELIGIBLE")

    assignment.assignment_state = "ACTIVE"
    assignment.updated_by = p.user_id
    db.add(
        AuditEvent(
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            action="ADMIN_AGENT_VOICE_ASSIGNMENT_ACTIVATED",
            resource_type="agent_voice_assignment",
            resource_id=assignment.id,
            outcome="SUCCESS",
            metadata_json={
                "agent_slug": assignment.agent_slug,
                "voice_catalog_id": voice.id,
                "validation_status": assignment.validation_status,
                "assignment_state": assignment.assignment_state,
                "evidence_ref": body.evidence_ref,
            },
        )
    )
    db.commit()
    return _admin_voice_assignment_payload(assignment, voice)


@router.post("/admin/agent-voice-assignments/{assignment_id}/deactivation")
def admin_deactivate_agent_voice_assignment(
    assignment_id: str,
    body: AdminVoiceAssignmentDeactivationRequest,
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _require_console_superadmin(p, settings)
    assignment = _tenant_voice_assignment_or_404(
        db,
        tenant_id=p.tenant_id,
        assignment_id=assignment_id,
    )
    if not assignment.active or assignment.assignment_state == "DISABLED":
        raise HTTPException(409, "VOICE_ASSIGNMENT_ALREADY_DISABLED")
    assignment.active = False
    assignment.assignment_state = "DISABLED"
    assignment.updated_by = p.user_id
    voice = db.get(VoiceCatalogEntry, assignment.voice_catalog_id)
    if voice is None:
        raise HTTPException(409, "VOICE_CATALOG_ENTRY_NOT_FOUND")
    db.add(
        AuditEvent(
            tenant_id=p.tenant_id,
            actor_id=p.user_id,
            action="ADMIN_AGENT_VOICE_ASSIGNMENT_DEACTIVATED",
            resource_type="agent_voice_assignment",
            resource_id=assignment.id,
            outcome="SUCCESS",
            metadata_json={
                "agent_slug": assignment.agent_slug,
                "evidence_ref": body.evidence_ref,
            },
        )
    )
    db.commit()
    db.refresh(assignment)
    return _admin_voice_assignment_payload(assignment, voice)


@router.get("/admin/teams")
def admin_teams(
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
):
    _require_console_superadmin(p, settings)
    return [team_definition_payload(team, settings) for team in list_team_definitions()]


@router.get("/admin/governance")
def admin_governance(
    p: Principal = Depends(require_provisioned_superadmin),
    settings: Settings = Depends(get_settings),
):
    _require_console_superadmin(p, settings)
    return {
        "tenant_id": p.tenant_id,
        "environment": settings.environment,
        "release_sha": settings.release_sha,
        "access_gate_enabled": settings.access_gate_enabled,
        "artifacts_enabled": settings.artifacts_enabled,
        "realtime_streaming_enabled": settings.realtime_streaming_enabled,
        "voice_enabled": settings.voice_enabled,
        "llm_primary_provider": settings.llm_primary_provider,
    }

@router.get("/agents")
def agents_catalog(
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
):
    admin = bool({"admin", "orkio_admin", "owner", "superadmin", "platform_owner"}.intersection(p.roles))
    catalog = list_agents()
    if not admin:
        catalog = tuple(agent for agent in catalog if agent.slug.lower() == "orkio")
    return [{
        "slug": a.slug,
        "canonical_name": a.canonical_name,
        "display_name": a.display_name,
        "role_code": a.role_code,
        "role_label": a.role_label,
        "organizational_level": a.organizational_level,
        "department": a.department,
        "founder_direct_access": a.founder_direct_access,
        "localized_names": dict(a.localized_names),
        "localized_role_labels": dict(a.localized_role_labels),
        "target_kind": a.target_kind.value,
        "availability": availability_for(a, settings).to_dict(),
    } for a in catalog]


@router.get("/agents/by-id/{agent_id}/readiness")
async def agent_readiness(
    agent_id: str,
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
):
    try:
        probe = await readiness_probe_for_id(agent_id, settings)
    except AgentNotFound as exc:
        raise HTTPException(404, "AGENT_NOT_FOUND") from exc
    return probe.to_dict()


def _resolve_target_or_404(requested_target: str, settings: Settings):
    try:
        return resolve_direct_target_decision(requested_target, settings)
    except TargetAmbiguous as exc:
        raise HTTPException(
            409,
            detail={"code": exc.code, "candidates": list(exc.candidates)},
        ) from exc
    except TargetNotFound as exc:
        raise HTTPException(404, detail={"code": exc.code}) from exc


def _effective_agent_target(requested_target: str, p: Principal) -> str:
    if {"admin", "orkio_admin"}.intersection(p.roles):
        return requested_target
    # O resolver mantém IDs técnicos no namespace explícito `id:<slug>`.
    # Retornar o slug cru aqui fazia o Co-Criador cair em TARGET_NOT_FOUND.
    return "id:orkio"

INVITE_ALLOWED_ROLES={ThreadRole.owner.value, ThreadRole.moderator.value}

def thread_access(db: Session, thread_id: str, p: Principal) -> tuple[Thread, ThreadParticipant]:
    try:
        decision = require_thread_access(
            db, thread_id=thread_id, tenant_id=p.tenant_id, user_id=p.user_id
        )
    except ThreadAccessPolicyError as exc:
        raise HTTPException(exc.status_code, exc.code) from exc
    return decision.thread, decision.participant


def _history(
    db: Session,
    thread_id: str,
    tenant_id: str,
    settings: Settings,
    limit: int = 40,
    extra_system_messages: list[dict[str, str]] | None = None,
    *,
    participant: ThreadParticipant,
    user_id: str | None = None,
    execution_id: str | None = None,
    agent_id: str | None = None,
    purpose: str = "chat",
) -> list[dict]:
    rows = visible_messages(
        db, thread_id=thread_id, tenant_id=tenant_id,
        participant=participant, limit=limit, newest_first=True,
    )
    ordered=list(reversed(rows))
    projection=project_direct_history(
        ordered,
        turn_owner_agent_id=agent_id,
    )
    history=list(projection.messages)
    history_policy_logger.info(
        "DIRECT_HISTORY_PROJECTED tenant_id=%s thread_id=%s owner_agent_id=%s policy=%s "
        "user_count=%s owner_assistant_count=%s cross_agent_context_count=%s cross_agent_ids=%s",
        tenant_id,
        thread_id,
        (agent_id or "").strip(),
        DIRECT_HISTORY_POLICY_VERSION,
        projection.user_count,
        projection.owner_assistant_count,
        projection.cross_agent_context_count,
        ",".join(projection.cross_agent_ids),
    )
    latest_user_content=next(
        (str(m.content or "") for m in reversed(ordered) if m.author_type=="user"),
        "",
    )
    system_guard=system_capability_guard_message(latest_user_content)
    context=document_context_message(
        db,
        settings=settings,
        tenant_id=tenant_id,
        thread_id=thread_id,
        query_text=latest_user_content,
    )
    system_messages=list(extra_system_messages or [])
    if system_guard:
        system_messages.append(system_guard)
    if user_id and execution_id:
        system_messages.extend(
            knowledge_context_messages(
                db,
                settings=settings,
                tenant_id=tenant_id,
                user_id=user_id,
                purpose=purpose,
                execution_id=execution_id,
                thread_id=thread_id,
                agent_id=agent_id,
                query_text=latest_user_content,
            )
        )
    if context:
        system_messages.append(context)
    persisted_artifacts = artifact_context_message(
        db,
        tenant_id=tenant_id,
        thread_id=thread_id,
    )
    if persisted_artifacts:
        system_messages.append(persisted_artifacts)
    return system_messages + history

@router.get("/health")
def health(settings: Settings=Depends(get_settings)):
    return {"status":"ok","release":"2.0.0a1","sha":settings.release_sha,"environment":settings.environment}

EXPECTED_MIGRATION_HEAD = "013_agent_studio_control_plane"


@router.get("/ready")
def ready(settings: Settings=Depends(get_settings), db: Session=Depends(get_db)):
    """Readiness estrito, separado do liveness.

    Retorna HTTP 200 somente quando banco, schema e migration estão prontos.
    Nunca expõe URL de conexão, usuário, host ou credencial.
    """
    checks: dict[str, object] = {}

    try:
        db.execute(text("SELECT 1"))
        checks["database_connect"] = True
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unavailable",
                "checks": {"database_connect": False},
            },
        ) from exc

    expected = set(Base.metadata.tables)
    try:
        from sqlalchemy import inspect as _inspect

        present = set(_inspect(db.get_bind()).get_table_names())
    except Exception:
        present = set()

    missing = sorted(expected - present)
    checks["schema_complete"] = not missing
    if missing:
        checks["missing_tables"] = missing

    try:
        current_heads = {
            str(row[0])
            for row in db.execute(
                text("SELECT version_num FROM alembic_version")
            ).all()
            if row[0]
        }
    except Exception:
        current_heads = set()

    checks["migration_head"] = (
        next(iter(current_heads)) if len(current_heads) == 1 else None
    )
    checks["migration_expected"] = EXPECTED_MIGRATION_HEAD
    checks["migration_current"] = (
        current_heads == {EXPECTED_MIGRATION_HEAD}
    )
    checks["driver"] = str(db.get_bind().dialect.name)

    ok = (
        checks["database_connect"] is True
        and checks["schema_complete"] is True
        and checks["migration_current"] is True
    )
    if not ok:
        raise HTTPException(
            status_code=503,
            detail={"status": "unavailable", "checks": checks},
        )
    return {"status": "ready", "checks": checks}

@router.get("/governance/status")
def governance(settings: Settings=Depends(get_settings)):
    return {
      "auth_mode": settings.auth_mode,
      "realtime_streaming_enabled": settings.realtime_streaming_enabled,
      "realtime_voice_enabled": settings.voice_enabled,
      "github_readonly_enabled": settings.github_enabled,
      "artifacts_enabled": settings.artifacts_enabled,
      "assisted_evolution_enabled": settings.assisted_evolution_enabled,
      "evolution_execution_allowed": settings.evolution_execution_allowed,
      "human_approval_required": settings.human_approval_required,
      "llm_configured": bool((settings.openai_api_key or "").strip()),
    }

@router.get("/integrations/github/repositories")
def github_repositories(
    p: Principal = Depends(require_provisioned_admin),
    settings: Settings = Depends(get_settings),
):
    if not settings.github_enabled:
        raise HTTPException(403, "GITHUB_INTEGRATION_DISABLED")
    return {
        "repositories": list(allowed_repositories(settings)),
        "read_only": True,
        "proposal_only": True,
        "write_executed": False,
    }


@router.post("/integrations/github/snapshot")
async def github_snapshot(
    payload: GitHubSnapshotRequest,
    p: Principal = Depends(require_provisioned_admin),
    settings: Settings = Depends(get_settings),
):
    try:
        snapshot = await repository_snapshot(
            settings,
            payload.repository,
            requested_paths=payload.paths,
        )
    except GitHubIntegrationError as exc:
        raise HTTPException(
            status_code=422 if "PATH" in (exc.args[0] if exc.args else exc.code) else 503,
            detail={"code": exc.args[0] if exc.args else exc.code},
        ) from exc
    return {
        "provenance": snapshot.provenance(),
        "tree_paths": list(snapshot.tree_paths),
        "files": [
            {
                "path": item.path,
                "sha256": item.sha256,
                "github_blob_sha": item.github_blob_sha,
                "size": item.size,
                "text": item.text,
            }
            for item in snapshot.files
        ],
    }



@router.get("/tools/capabilities")
def tool_capabilities(
    p: Principal = Depends(require_provisioned_principal),
):
    try:
        policy = CapabilityPolicy.from_env()
    except CapabilityPolicyError as exc:
        raise HTTPException(503, detail={"code": getattr(exc, "code", "CAPABILITY_POLICY_ERROR")}) from exc
    return policy.manifest(privileged=privileged_roles(p.roles))


@router.post("/tools/python/execute")
async def tool_python_execute(
    payload: PythonExecuteRequest,
    p: Principal = Depends(require_provisioned_admin),
    db: Session = Depends(get_db),
):
    try:
        policy = CapabilityPolicy.from_env()
        result = await execute_python_runtime(
            code=payload.code,
            policy=policy,
            context=PythonRuntimeContext(
                tenant_id=p.tenant_id,
                user_id=p.user_id,
            ),
            db=db,
        )
    except (CapabilityPolicyError, PythonToolError, PythonRuntimeError) as exc:
        code = exc.args[0] if exc.args else getattr(exc, "code", "PYTHON_RUNTIME_ERROR")
        if "DISABLED" in code or "FORBIDDEN" in code:
            status = 403
        elif "UNAVAILABLE" in code:
            status = 503
        else:
            status = 422
        raise HTTPException(status, detail={"code": code}) from exc
    return {
        "execution_id": result.execution_id,
        "sandbox_execution_id": result.sandbox_execution_id,
        "status": result.status,
        "code_sha256": result.code_sha256,
        "runtime": result.sandbox_provider,
        "runtime_profile_id": result.runtime_profile_id,
        "runtime_profile_digest": result.runtime_profile_digest,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "truncated": result.truncated,
        "network_policy": result.network_policy,
        "network_policy_enforced": result.network_policy_enforced,
        "filesystem_isolation_enforced": result.filesystem_isolation_enforced,
        "cpu_limit_enforced": result.cpu_limit_enforced,
        "memory_limit_enforced": result.memory_limit_enforced,
        "process_limit_enforced": result.process_limit_enforced,
        "ephemeral_filesystem_enforced": result.ephemeral_filesystem_enforced,
        "no_operational_secrets": result.no_operational_secrets,
        "attestation": result.attestation,
        "audit_ref": result.audit_ref,
        "execution_performed": result.execution_performed,
        "external_write": False,
        "proposal_only": False,
    }


@router.post("/tools/external/read")
async def tool_external_read(
    payload: ExternalReadRequest,
    p: Principal = Depends(require_provisioned_admin),
):
    try:
        policy = CapabilityPolicy.from_env()
        result = await read_external_url(payload.url, policy)
    except (CapabilityPolicyError, ExternalReadError) as exc:
        code = exc.args[0] if exc.args else getattr(exc, "code", "EXTERNAL_READ_ERROR")
        status = 403 if "DISABLED" in code or "NOT_ALLOWED" in code else 422
        raise HTTPException(status, detail={"code": code}) from exc
    return {
        "url": result.url,
        "final_url": result.final_url,
        "content_type": result.content_type,
        "status_code": result.status_code,
        "size": result.size,
        "sha256": result.sha256,
        "text": result.text,
        "read_only": True,
        "proposal_only": True,
    }


@router.post("/threads")
def create_thread(payload: ThreadCreate, p: Principal=Depends(require_provisioned_principal), db: Session=Depends(get_db)):
    thread=Thread(tenant_id=p.tenant_id,title=payload.title,created_by=p.user_id)
    db.add(thread); db.flush()
    db.add(ThreadParticipant(tenant_id=p.tenant_id,thread_id=thread.id,user_id=p.user_id,thread_role="owner",
                             can_view_attachments=True,can_download_artifacts=True,can_upload_files=True,can_generate_artifacts=True))
    db.commit()
    return {"id":thread.id,"title":thread.title}

@router.patch("/threads/{thread_id}")
def update_thread_title(
    thread_id: str,
    payload: ThreadTitleUpdate,
    p: Principal = Depends(require_provisioned_principal),
    db: Session = Depends(get_db),
):
    thread, member = thread_access(db, thread_id, p)
    if member.thread_role not in INVITE_ALLOWED_ROLES:
        raise HTTPException(403, "THREAD_RENAME_ROLE_REQUIRED")
    title = payload.title.strip()
    if not title:
        raise HTTPException(422, "THREAD_TITLE_REQUIRED")
    thread.title = title
    db.add(thread)
    db.commit()
    db.refresh(thread)
    return {"id": thread.id, "title": thread.title}

@router.get("/threads")
def list_threads(p: Principal=Depends(require_provisioned_principal), db: Session=Depends(get_db),
                 limit: int=Query(50, ge=1, le=200), offset: int=Query(0, ge=0)):
    """Lista apenas as threads do tenant nas quais o principal participa.

    Ordenação determinística por created_at desc e id desc, para que a
    paginação seja estável mesmo com timestamps iguais.
    """
    stmt=(select(Thread, ThreadParticipant.thread_role)
          .join(ThreadParticipant, ThreadParticipant.thread_id==Thread.id)
          .where(Thread.tenant_id==p.tenant_id,
                 ThreadParticipant.tenant_id==p.tenant_id,
                 ThreadParticipant.user_id==p.user_id,
                 ThreadParticipant.active.is_(True))
          .order_by(Thread.created_at.desc(), Thread.id.desc())
          .limit(limit).offset(offset))
    rows=db.execute(stmt).all()
    total=db.scalar(select(func.count()).select_from(ThreadParticipant)
                    .where(ThreadParticipant.tenant_id==p.tenant_id,
                           ThreadParticipant.user_id==p.user_id,
                           ThreadParticipant.active.is_(True))) or 0
    return {"items":[{"id":t.id,"title":t.title,"created_at":t.created_at,"thread_role":role} for t,role in rows],
            "total":int(total),"limit":limit,"offset":offset}

@router.get("/threads/{thread_id}/messages")
def list_messages(thread_id: str,p:Principal=Depends(require_provisioned_principal),db:Session=Depends(get_db)):
    # Canonical access governs the history scope; never infer display names
    # across tenants or threads, even if a global user ID is present.
    _, member = thread_access(db, thread_id, p)
    rows = visible_messages(
        db, thread_id=thread_id, tenant_id=p.tenant_id, participant=member,
    )
    human_author_ids = {
        m.author_id for m in rows if m.author_type == "user" and m.author_id
    }
    human_names = {}
    if human_author_ids:
        human_names = dict(
            db.execute(
                select(User.id, User.display_name)
                .join(ThreadParticipant, ThreadParticipant.user_id == User.id)
                .where(
                    ThreadParticipant.tenant_id == p.tenant_id,
                    ThreadParticipant.thread_id == thread_id,
                    ThreadParticipant.user_id.in_(human_author_ids),
                )
            ).all()
        )
    return [{
        "id":m.id,
        "author_type":m.author_type,
        "author_id":m.author_id if m.author_type == "user" and m.author_id in human_names else None,
        "user_id":m.author_id if m.author_type == "user" and m.author_id in human_names else None,
        "author_display_name":human_names.get(m.author_id) if m.author_type == "user" else None,
        "agent_id":m.author_id if m.author_type=="agent" else None,
        "agent_name":m.agent_name,
        "content":m.content,
        "created_at":m.created_at,
    } for m in rows]

@router.post("/threads/{thread_id}/messages")
async def send_message(thread_id:str,payload:MessageCreate,p:Principal=Depends(require_provisioned_principal),
                       settings:Settings=Depends(get_settings),db:Session=Depends(get_db)):
    _,member=thread_access(db,thread_id,p)
    if member.thread_role==ThreadRole.viewer.value: raise HTTPException(403,"THREAD_READ_ONLY")
    effective_agent = _effective_agent_target(payload.agent, p)
    decision=_resolve_target_or_404(effective_agent, settings)
    execution=decision.execution
    availability=decision.availability
    turn=build_direct_turn(
        execution=execution,
        thread_id=thread_id,
        tenant_id=p.tenant_id,
        user_id=p.user_id,
        requested_target=effective_agent,
        channel=RuntimeChannel.CHAT_JSON,
    )
    audit_candidate, audit_invocation_message, natural_audit_binding = _resolve_audit_request(
        payload.content,
        resolved_agent_id=turn.resolved_agent_id,
    )
    if audit_candidate:
        _audit_trace_turn(
            "natural_request_received" if natural_audit_binding is not None else "directive_received",
            turn=turn,
            settings=settings,
            capability_id=(
                natural_audit_binding.required_capability_id
                if natural_audit_binding is not None
                else None
            ),
            operation=(
                natural_audit_binding.intent
                if natural_audit_binding is not None
                else None
            ),
            status="accepted",
        )
    observer=ExecutionObserver.from_turn(turn,execution_engine=execution.execution_engine.value)
    observer.start()
    try:
        llm.ensure_configured(settings)
    except (GitHubIntegrationError, asyncio.TimeoutError) as exc:
        observer.fail("GITHUB_TOOL_FAILED")
        raise HTTPException(503, "GITHUB_TOOL_FAILED") from exc
    except llm.LLMNotConfigured:
        observer.fail("LLM_NOT_CONFIGURED")
        raise HTTPException(503,"LLM_NOT_CONFIGURED")

    user=Message(tenant_id=p.tenant_id,thread_id=thread_id,author_type="user",author_id=p.user_id,content=payload.content)
    db.add(user); db.commit()

    audit_outcome: AuditInvocationOutcome | None = None
    if audit_candidate:
        if natural_audit_binding is not None and not natural_audit_binding.executable:
            code = natural_audit_binding.error_code or "CAPABILITY_UNAVAILABLE"
            observer.fail(code)
            _audit_trace_turn(
                "natural_request_unavailable",
                turn=turn,
                settings=settings,
                capability_id=natural_audit_binding.required_capability_id,
                operation=natural_audit_binding.intent,
                status="failed",
                error_code=code,
            )
            raise _natural_audit_http_error(natural_audit_binding)
        try:
            audit_outcome = _audit_invocation_service(db, settings).invoke_if_directive(
                message=audit_invocation_message or payload.content,
                turn=turn,
                principal_roles=p.roles,
            )
        except AuditInvocationError as exc:
            observer.fail(exc.code)
            raise HTTPException(exc.http_status, detail=_audit_error_detail(exc)) from exc

    hyper_surface = execution.resolved_target == "orkio"
    profile = (
        profile_for(db, tenant_id=p.tenant_id, user_id=p.user_id)
        if hyper_surface
        else None
    )
    if audit_candidate:
        logging.getLogger("orkio.self_knowledge").info(
            "self_knowledge.github_bypassed execution_id=%s reason=governed_audit",
            turn.execution_id,
        )
        # Governed audit V1 is a single-capability, network=false path. Do not
        # run GitHub/Python/external-read side paths for the same directive.
        github_messages = []
        capability_messages = []
        runtime_system_messages = (
            [audit_outcome.system_message()] if audit_outcome is not None else []
        )
        if audit_outcome is not None:
            _audit_trace_turn(
                "evidence_attached_to_turn",
                turn=turn,
                settings=settings,
                capability_id=audit_outcome.capability_id,
                operation=audit_outcome.operation,
                audit_execution_id=audit_outcome.audit_execution_id,
                status=audit_outcome.status,
            )
    else:
        github_messages = await github_context_messages(
            settings,
            message=payload.content,
            is_admin=is_allowlisted_admin(p, settings),
            execution_id=turn.execution_id,
        )
        capability_messages = await runtime_capability_messages(
            message=payload.content,
            roles=p.roles,
            tenant_id=p.tenant_id,
            user_id=p.user_id,
            thread_id=thread_id,
            agent_id=turn.turn_owner_agent_id,
            request_id=turn.execution_id,
            db=db,
        )
        runtime_system_messages = list(github_messages) + list(capability_messages)
    if hyper_surface:
        runtime_system_messages.insert(
            0,
            hyper_cocreator_system_message(
                co_creator_name=profile.co_creator_name if profile else None,
                onboarding_goal=profile.onboarding_goal if profile else None,
            ),
        )
        runtime_system_messages.insert(
            1,
            hyper_cocreator_profile_message(
                co_creator_name=profile.co_creator_name if profile else None,
                onboarding_goal=profile.onboarding_goal if profile else None,
            ),
        )
    history=_history(
        db,
        thread_id,
        p.tenant_id,
        settings,
        extra_system_messages=runtime_system_messages,
        participant=member,
        user_id=p.user_id,
        execution_id=turn.execution_id,
        agent_id=turn.turn_owner_agent_id,
        purpose="chat",
    )

    try:
        if settings.github_agent_tools_enabled and not audit_candidate:
            history = await prepare_github_tool_history(
                settings, execution.resolved_target, history,
                tenant_id=p.tenant_id, user_id=p.user_id,
                execution_id=turn.execution_id,
                is_admin=is_allowlisted_admin(p, settings),
            )
        answer=await llm.generate(settings,execution.resolved_target,history)
    except (GitHubIntegrationError, asyncio.TimeoutError):
        observer.fail("GITHUB_TOOL_FAILED")
        raise HTTPException(502, "GITHUB_TOOL_FAILED")
    except llm.LLMNotConfigured:
        observer.fail("LLM_NOT_CONFIGURED")
        raise HTTPException(503,"LLM_NOT_CONFIGURED")
    except llm.LLMUpstreamError as exc:
        observer.fail("LLM_UPSTREAM_ERROR")
        llm_runtime_logger.error(
            "LLM_PROVIDER_FAILURE %s",
            json.dumps(
                {
                    "request_id": turn.request_id,
                    "execution_id": turn.execution_id,
                    "tenant_id": turn.tenant_id,
                    "thread_id": turn.thread_id,
                    "agent_id": turn.turn_owner_agent_id,
                    "route_family": turn.route_family.value,
                    **exc.diagnostic(),
                },
                sort_keys=True,
            ),
        )
        raise HTTPException(502,"LLM_UPSTREAM_ERROR")

    assistant,envelope=persist_agent_response(db,turn=turn,content=answer)
    observer.persisted(message_id=assistant.id)
    observer.complete()
    response_payload = {
        "message_id":assistant.id,
        "execution_id":turn.execution_id,
        "agent_id":envelope.agent_id,
        "agent_name":envelope.agent_name,
        "content":envelope.content,
        "execution":{
            "request_id":turn.request_id,
            "execution_id":turn.execution_id,
            "resolved_target":execution.resolved_target,
            "turn_owner":execution.turn_owner,
            "display_agent_id":turn.display_agent_id,
            "execution_engine":execution.execution_engine.value,
            "ownership_locked":execution.ownership_locked,
            "chat_availability":{
                "status":availability.chat.status.value,
                "eligible":availability.chat.eligible,
                "reason_code":availability.chat.reason_code,
            },
        },
        "response":envelope_payload(envelope),
    }
    if audit_outcome is not None:
        response_payload["audit"] = audit_outcome.reference()
    return response_payload

@router.post("/threads/{thread_id}/stream")
async def stream_message(thread_id:str,payload:MessageCreate,p:Principal=Depends(require_provisioned_principal),
                         settings:Settings=Depends(get_settings),db:Session=Depends(get_db)):
    """SSE com contrato terminal garantido.

    Todo caminho emite event: done, inclusive após event: error, para que
    o cliente nunca fique com o input travado. A transação de banco é
    fechada antes da chamada ao provedor de LLM.
    """
    _,member=thread_access(db,thread_id,p)
    if member.thread_role==ThreadRole.viewer.value: raise HTTPException(403,"THREAD_READ_ONLY")
    if not settings.realtime_streaming_enabled: raise HTTPException(403,"REALTIME_STREAMING_DISABLED")
    effective_agent = _effective_agent_target(payload.agent, p)
    decision=_resolve_target_or_404(effective_agent, settings)
    execution=decision.execution
    availability=decision.availability
    turn=build_direct_turn(
        execution=execution,
        thread_id=thread_id,
        tenant_id=p.tenant_id,
        user_id=p.user_id,
        requested_target=effective_agent,
        channel=RuntimeChannel.CHAT_SSE,
    )
    audit_candidate, audit_invocation_message, natural_audit_binding = _resolve_audit_request(
        payload.content,
        resolved_agent_id=turn.resolved_agent_id,
    )
    if audit_candidate:
        _audit_trace_turn(
            "natural_request_received" if natural_audit_binding is not None else "directive_received",
            turn=turn,
            settings=settings,
            capability_id=(
                natural_audit_binding.required_capability_id
                if natural_audit_binding is not None
                else None
            ),
            operation=(
                natural_audit_binding.intent
                if natural_audit_binding is not None
                else None
            ),
            status="accepted",
        )

    internal_contributions = ()
    internal_consultation_plans = ()
    configured=True
    try:
        llm.ensure_configured(settings)
    except llm.LLMNotConfigured:
        configured=False

    agent=execution.resolved_target
    tenant_id=p.tenant_id
    user_id=p.user_id
    artifact_intent=None if audit_candidate else detect_artifact_intent(payload.content)
    artifact_allowed=bool(
        artifact_intent
        and settings.artifacts_enabled
        and member.can_generate_artifacts
    )
    if artifact_intent is not None:
        artifact_gate_logger.info(
            "ARTIFACT_GATE %s",
            json.dumps(
                {
                    "event": "artifact_gate_evaluated",
                    "execution_id": turn.execution_id,
                    "thread_id": thread_id,
                    "requested_agent": effective_agent,
                    "resolved_agent": turn.resolved_agent_id,
                    "requested_format": artifact_intent.requested_format,
                    "artifacts_enabled": bool(settings.artifacts_enabled),
                    "can_generate_artifacts": bool(member.can_generate_artifacts),
                    "artifact_allowed": artifact_allowed,
                    "environment": settings.environment,
                    "release_sha": settings.release_sha,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
        )

    audit_outcome: AuditInvocationOutcome | None = None
    audit_error: AuditInvocationError | None = None
    if configured:
        db.add(Message(tenant_id=tenant_id,thread_id=thread_id,author_type="user",author_id=user_id,content=payload.content))
        db.commit()
        if audit_candidate:
            if natural_audit_binding is not None and not natural_audit_binding.executable:
                code = natural_audit_binding.error_code or "CAPABILITY_UNAVAILABLE"
                audit_error = AuditInvocationError(
                    code,
                    http_status=(501 if code == "CAPABILITY_UNAVAILABLE" else 400),
                )
                _audit_trace_turn(
                    "natural_request_unavailable",
                    turn=turn,
                    settings=settings,
                    capability_id=natural_audit_binding.required_capability_id,
                    operation=natural_audit_binding.intent,
                    status="failed",
                    error_code=code,
                )
            else:
                try:
                    audit_outcome = _audit_invocation_service(db, settings).invoke_if_directive(
                        message=audit_invocation_message or payload.content,
                        turn=turn,
                        principal_roles=p.roles,
                    )
                except AuditInvocationError as exc:
                    audit_error = exc
        hyper_surface = execution.resolved_target == "orkio"
        profile = (
            profile_for(db, tenant_id=tenant_id, user_id=user_id)
            if hyper_surface
            else None
        )
        if audit_candidate:
            logging.getLogger("orkio.self_knowledge").info(
                "self_knowledge.github_bypassed execution_id=%s reason=governed_audit",
                turn.execution_id,
            )
            github_messages = []
            capability_messages = []
        else:
            github_messages = await github_context_messages(
                settings,
                message=payload.content,
                is_admin=is_allowlisted_admin(p, settings),
                execution_id=turn.execution_id,
            )
            capability_messages = await runtime_capability_messages(
                message=payload.content,
                roles=p.roles,
                tenant_id=p.tenant_id,
                user_id=p.user_id,
                thread_id=thread_id,
                agent_id=turn.turn_owner_agent_id,
                request_id=turn.execution_id,
                db=db,
            )
        if hyper_surface and settings.internal_agent_consultation_enabled:
            try:
                internal_contributions, internal_consultation_plans = (
                    await build_internal_consultation_context(
                        settings,
                        turn=turn,
                        message=payload.content,
                    )
                )
            except InternalConsultationError:
                internal_consultation_logger.warning(
                    "INTERNAL_CONSULTATION_FAILED execution_id=%s thread_id=%s",
                    turn.execution_id,
                    thread_id,
                )
        runtime_system_messages = (
            list(github_messages)
            + internal_contribution_messages(internal_contributions)
            + list(capability_messages)
        )
        if audit_outcome is not None:
            runtime_system_messages.append(audit_outcome.system_message())
            _audit_trace_turn(
                "evidence_attached_to_turn",
                turn=turn,
                settings=settings,
                capability_id=audit_outcome.capability_id,
                operation=audit_outcome.operation,
                audit_execution_id=audit_outcome.audit_execution_id,
                status=audit_outcome.status,
            )
        if hyper_surface:
            runtime_system_messages.insert(
                0,
                hyper_cocreator_system_message(
                    co_creator_name=profile.co_creator_name if profile else None,
                    onboarding_goal=profile.onboarding_goal if profile else None,
                ),
            )
            runtime_system_messages.insert(
                1,
                hyper_cocreator_profile_message(
                    co_creator_name=profile.co_creator_name if profile else None,
                    onboarding_goal=profile.onboarding_goal if profile else None,
                ),
            )
        if artifact_allowed and artifact_intent is not None:
            runtime_system_messages.append(
                artifact_generation_system_message(artifact_intent)
            )
        history=_history(
            db,
            thread_id,
            tenant_id,
            settings,
            extra_system_messages=runtime_system_messages,
            participant=member,
            user_id=user_id,
            execution_id=turn.execution_id,
            agent_id=turn.turn_owner_agent_id,
            purpose="chat",
        )
    else:
        history=[]

    def sse_event(event: RuntimeEvent) -> str:
        data=dict(event.data)
        data.setdefault("execution_id", event.execution_id)
        data.setdefault("sequence", event.sequence)
        return f"event: {event.event_type.value}\ndata: {json.dumps(data,ensure_ascii=False)}\n\n"

    correlation=ExecutionCorrelation(
        request_id=turn.request_id,
        execution_id=turn.execution_id,
        tenant_id=turn.tenant_id,
        thread_id=turn.thread_id,
        owner_agent_id=turn.turn_owner_agent_id,
        execution_engine=execution.execution_engine.value,
    )
    observer=ExecutionObserver.from_turn(turn,execution_engine=execution.execution_engine.value)
    observer.start()
    if internal_contributions:
        observer.consulted(
            count=len(internal_contributions),
            domains=[contribution.purpose for contribution in internal_contributions],
        )

    async def events():
        emitted:list[RuntimeEvent]=[]
        sequence=1

        def event(kind: RuntimeEventType, **data: object) -> RuntimeEvent:
            nonlocal sequence
            item=RuntimeEvent(kind, turn.execution_id, sequence, correlation.event_data(**data))
            sequence += 1
            emitted.append(item)
            return item

        def terminal(kind: RuntimeEventType, **data: object) -> RuntimeEvent:
            item=event(kind, **data)
            validate_runtime_sequence(tuple(emitted))
            return item

        if not configured:
            observer.fail("LLM_NOT_CONFIGURED")
            yield sse_event(event(RuntimeEventType.ERROR,code="LLM_NOT_CONFIGURED",message="Integração de linguagem não configurada."))
            yield sse_event(terminal(RuntimeEventType.DONE,status="failed"))
            return

        if audit_error is not None:
            observer.fail(audit_error.code)
            error_data: dict[str, object] = {"code": audit_error.code}
            audit_ref = audit_error.audit_reference or {}
            if audit_error.audit_reference is not None:
                error_data["audit"] = audit_error.audit_reference
            yield sse_event(event(RuntimeEventType.ERROR, **error_data))
            _audit_trace_turn(
                "sse_terminal",
                turn=turn,
                settings=settings,
                capability_id=(
                    str(audit_ref.get("capability_id"))
                    if audit_ref.get("capability_id") is not None
                    else None
                ),
                audit_execution_id=(
                    str(audit_ref.get("audit_execution_id"))
                    if audit_ref.get("audit_execution_id") is not None
                    else None
                ),
                status="failed",
                error_code=audit_error.code,
            )
            yield sse_event(terminal(RuntimeEventType.DONE,status="failed"))
            return

        status_data: dict[str, object] = {}
        if audit_outcome is not None:
            status_data["audit"] = audit_outcome.reference()
        yield sse_event(event(
            RuntimeEventType.STATUS,
            status="started",
            agent=agent,
            agent_id=turn.turn_owner_agent_id,
            ownership_locked=turn.ownership_locked,
            chat_availability=availability.chat.status.value,
            internal_consultation=bool(internal_contributions),
            **status_data,
        ))
        parts:list[str]=[]
        tool_history = history
        try:
            if settings.github_agent_tools_enabled and not audit_candidate:
                tool_history = await prepare_github_tool_history(
                    settings, agent, history,
                    tenant_id=tenant_id, user_id=user_id,
                    execution_id=turn.execution_id,
                    is_admin=is_allowlisted_admin(p, settings),
                )
            async for piece in llm.stream(settings,agent,tool_history):
                parts.append(piece)
                yield sse_event(event(RuntimeEventType.CHUNK,text=piece))
        except (GitHubIntegrationError, asyncio.TimeoutError):
            observer.fail("GITHUB_TOOL_FAILED")
            yield sse_event(event(RuntimeEventType.ERROR,code="GITHUB_TOOL_FAILED"))
            yield sse_event(terminal(RuntimeEventType.DONE,status="failed"))
            return
        except llm.LLMNotConfigured:
            observer.fail("LLM_NOT_CONFIGURED")
            yield sse_event(event(RuntimeEventType.ERROR,code="LLM_NOT_CONFIGURED"))
            yield sse_event(terminal(RuntimeEventType.DONE,status="failed"))
            return
        except llm.LLMUpstreamError as exc:
            observer.fail("LLM_UPSTREAM_ERROR")
            llm_runtime_logger.error(
                "LLM_PROVIDER_FAILURE %s",
                json.dumps(
                    {
                        "request_id": turn.request_id,
                        "execution_id": turn.execution_id,
                        "tenant_id": turn.tenant_id,
                        "thread_id": turn.thread_id,
                        "agent_id": turn.turn_owner_agent_id,
                        "route_family": turn.route_family.value,
                        **exc.diagnostic(),
                    },
                    sort_keys=True,
                ),
            )
            yield sse_event(event(RuntimeEventType.ERROR,code="LLM_UPSTREAM_ERROR"))
            yield sse_event(terminal(RuntimeEventType.DONE,status="failed"))
            return
        except Exception as exc:
            observer.fail("LLM_UPSTREAM_ERROR")
            llm_runtime_logger.exception(
                "LLM_RUNTIME_FAILURE request_id=%s execution_id=%s tenant_id=%s thread_id=%s agent_id=%s exception_type=%s",
                turn.request_id,
                turn.execution_id,
                turn.tenant_id,
                turn.thread_id,
                turn.turn_owner_agent_id,
                type(exc).__name__,
            )
            yield sse_event(event(RuntimeEventType.ERROR,code="LLM_UPSTREAM_ERROR"))
            yield sse_event(terminal(RuntimeEventType.DONE,status="failed"))
            return

        answer="".join(parts).strip()
        if not answer:
            observer.fail("LLM_EMPTY_RESPONSE")
            yield sse_event(event(RuntimeEventType.ERROR,code="LLM_EMPTY_RESPONSE"))
            yield sse_event(terminal(RuntimeEventType.DONE,status="failed"))
            return

        message_id=None
        try:
            row,envelope=persist_agent_response(db,turn=turn,content=answer)
            message_id=row.id
        except Exception:
            db.rollback()
            observer.fail("PERSISTENCE_FAILED")
            yield sse_event(event(RuntimeEventType.ERROR,code="PERSISTENCE_FAILED"))
            yield sse_event(terminal(RuntimeEventType.DONE,status="failed"))
            return

        generated_artifact=None
        artifact_error_code: str | None = None
        if artifact_allowed and artifact_intent is not None:
            try:
                validated=render_and_validate(
                    intent=artifact_intent,
                    content=answer,
                    filename=default_filename(
                        artifact_intent,
                        agent_name=turn.display_agent_name,
                    ),
                )
                generated_artifact=persist_validated_artifact(
                    db,
                    settings=settings,
                    tenant_id=tenant_id,
                    thread_id=thread_id,
                    created_by=user_id,
                    validated=validated,
                    source_message_sha256=hashlib.sha256(payload.content.encode("utf-8")).hexdigest(),
                    source_response_message_id=message_id,
                    agent_id=turn.turn_owner_agent_id,
                    storage=build_blob_storage(settings),
                )
            except ArtifactGenerationError as exc:
                artifact_error_code = getattr(exc, "code", "ARTIFACT_GENERATION_FAILED")
                artifact_gate_logger.warning(
                    "ARTIFACT_OPTIONAL_OUTPUT_FAILED %s",
                    json.dumps(
                        {
                            "event": "artifact_optional_output_failed",
                            "execution_id": turn.execution_id,
                            "thread_id": thread_id,
                            "message_id": message_id,
                            "error_code": artifact_error_code,
                            "storage_error": isinstance(exc, ArtifactStorageError),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                )
            except Exception:
                artifact_error_code = "ARTIFACT_GENERATION_FAILED"
                artifact_gate_logger.warning(
                    "ARTIFACT_OPTIONAL_OUTPUT_FAILED %s",
                    json.dumps(
                        {
                            "event": "artifact_optional_output_failed",
                            "execution_id": turn.execution_id,
                            "thread_id": thread_id,
                            "message_id": message_id,
                            "error_code": artifact_error_code,
                            "storage_error": False,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                )

        observer.persisted(message_id=message_id)
        observer.complete()
        done_payload=dict(
            status="completed",
            message_id=message_id,
            agent_id=envelope.agent_id,
            agent_name=envelope.agent_name,
            resolved_target=execution.resolved_target,
            turn_owner=execution.turn_owner,
            display_agent_id=turn.display_agent_id,
            ownership_locked=execution.ownership_locked,
            response=envelope_payload(envelope),
        )
        if audit_outcome is not None:
            done_payload["audit"] = audit_outcome.reference()
        if generated_artifact is not None:
            done_payload["artifact"]=artifact_payload(generated_artifact)
        if artifact_error_code is not None:
            done_payload["artifact_error"] = artifact_error_code
        if audit_outcome is not None:
            _audit_trace_turn(
                "sse_terminal",
                turn=turn,
                settings=settings,
                capability_id=audit_outcome.capability_id,
                operation=audit_outcome.operation,
                audit_execution_id=audit_outcome.audit_execution_id,
                status="completed",
            )
        yield sse_event(terminal(RuntimeEventType.DONE, **done_payload))

    return StreamingResponse(events(),media_type="text/event-stream",
                             headers={"Cache-Control":"no-store","X-Accel-Buffering":"no"})

@router.post("/threads/{thread_id}/invitations",response_model=InvitationOut)
def invite(thread_id:str,payload:InvitationCreate,p:Principal=Depends(require_provisioned_principal),
           settings:Settings=Depends(get_settings),db:Session=Depends(get_db)):
    thread,member=thread_access(db,thread_id,p)
    if member.thread_role not in INVITE_ALLOWED_ROLES:
        raise HTTPException(403,"INVITE_ROLE_REQUIRED")
    invitation,token=create_invitation(db,thread,payload,p,settings)
    db.commit()
    return InvitationOut(invitation_id=invitation.id,invitation_url=f"{settings.invitation_base_url}/{token}",expires_at=invitation.expires_at)

@router.post("/invitations/accept")
def accept(payload:InvitationAccept,p:Principal=Depends(require_known_principal),settings:Settings=Depends(get_settings),db:Session=Depends(get_db)):
    invitation=accept_invitation(db,payload.token,p,settings); db.commit()
    return {"status":"accepted","thread_id":invitation.thread_id}

@router.get("/threads/{thread_id}/participants")
def participants(thread_id:str,p:Principal=Depends(require_provisioned_principal),db:Session=Depends(get_db)):
    thread_access(db,thread_id,p)
    rows=db.scalars(select(ThreadParticipant).where(ThreadParticipant.thread_id==thread_id,ThreadParticipant.active.is_(True))).all()
    return [{"id":x.id,"user_id":x.user_id,"role":x.thread_role,"membership_type":x.membership_type} for x in rows]

_THREAD_DOCUMENT_ALLOWED_MIME = {
    "application/pdf",
    "text/plain",
    "text/csv",
    "text/markdown",
    "application/json",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
_THREAD_DOCUMENT_SUFFIX_MIME = {
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".json": "application/json",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


def _resolve_thread_document_upload_identity(file: UploadFile) -> tuple[str, str]:
    safe = PurePosixPath((file.filename or "file").replace("\\", "/")).name
    if not safe or safe in {".", ".."} or "\x00" in safe:
        raise HTTPException(400, "FILENAME_INVALID")
    mime_type = (
        file.content_type
        if file.content_type in _THREAD_DOCUMENT_ALLOWED_MIME
        else _THREAD_DOCUMENT_SUFFIX_MIME.get(Path(safe).suffix.lower(), file.content_type)
    )
    if mime_type not in _THREAD_DOCUMENT_ALLOWED_MIME:
        raise HTTPException(415, "MIME_TYPE_NOT_ALLOWED")
    return safe, str(mime_type)


@router.get("/document-intake/capabilities")
def document_intake_capabilities(
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
):
    del p
    thread_context_enabled = bool(
        settings.artifacts_enabled
        and settings.unified_document_intake_enabled
        and settings.document_context_enabled
    )
    return {
        "large_paste": {
            "supported": True,
            "enabled": thread_context_enabled,
            "threshold_chars": int(settings.document_intake_large_paste_threshold_chars),
            "max_chars": int(settings.document_intake_large_paste_max_chars),
            "max_bytes": int(settings.document_intake_large_paste_max_bytes),
            "canonical_format": "text/markdown",
            "context_mode": "selective",
            "requires_explicit_confirmation": True,
        },
        "large_file": {
            "supported": True,
            "enabled": bool(
                thread_context_enabled
                and settings.large_document_pipeline_enabled
            ),
            "threshold_bytes": int(settings.max_upload_bytes),
            "max_bytes": int(settings.knowledge_large_document_max_upload_bytes),
            "canonical_format": "text/markdown",
            "context_mode": "selective",
            "requires_explicit_confirmation": False,
        },
    }


@router.post("/threads/{thread_id}/document-intake/paste")
def intake_large_paste(
    thread_id: str,
    payload: LargePasteIntakeRequest,
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    if not settings.artifacts_enabled:
        raise HTTPException(403, "ARTIFACTS_DISABLED")
    _, member = thread_access(db, thread_id, p)
    if member.thread_role == ThreadRole.viewer.value:
        raise HTTPException(403, "THREAD_READ_ONLY")
    if not member.can_upload_files:
        raise HTTPException(403, "UPLOAD_PERMISSION_REQUIRED")
    try:
        result = ingest_large_paste(
            db,
            settings=settings,
            principal=p,
            thread_id=thread_id,
            content=payload.content,
            title=payload.title,
        )
    except UnifiedDocumentIntakeError as exc:
        raise HTTPException(exc.status_code, exc.code) from exc
    return {
        "intake_status": "ready",
        "document_reference": result.attachment.id,
        "attachment_id": result.attachment.id,
        "filename": result.attachment.filename,
        "source_kind": "LARGE_PASTE",
        "source_sha256": result.source_sha256,
        "source_chars": result.source_chars,
        "canonical_sha256": result.canonical_sha256,
        "canonical_chars": result.canonical_chars,
        "sections": result.sections,
        "chunks": result.chunks,
        "context_mode": "selective",
        "reused": result.reused,
    }


@router.post("/threads/{thread_id}/document-intake/file")
async def intake_large_file_upload(
    thread_id: str,
    file: UploadFile = File(...),
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    if not settings.artifacts_enabled:
        raise HTTPException(403, "ARTIFACTS_DISABLED")
    _, member = thread_access(db, thread_id, p)
    if member.thread_role == ThreadRole.viewer.value:
        raise HTTPException(403, "THREAD_READ_ONLY")
    if not member.can_upload_files:
        raise HTTPException(403, "UPLOAD_PERMISSION_REQUIRED")
    safe, mime_type = _resolve_thread_document_upload_identity(file)
    try:
        result = await ingest_large_file(
            db,
            settings=settings,
            principal=p,
            thread_id=thread_id,
            file=file,
            filename=safe,
            mime_type=mime_type,
        )
    except UnifiedDocumentIntakeError as exc:
        raise HTTPException(exc.status_code, exc.code) from exc
    return {
        "intake_status": "ready",
        "document_reference": result.attachment.id,
        "attachment_id": result.attachment.id,
        "filename": result.source_filename,
        "canonical_filename": result.attachment.filename,
        "source_kind": "LARGE_FILE",
        "source_sha256": result.source_sha256,
        "source_size_bytes": result.source_size_bytes,
        "source_chars": result.source_chars,
        "canonical_sha256": result.canonical_sha256,
        "canonical_chars": result.canonical_chars,
        "sections": result.sections,
        "chunks": result.chunks,
        "context_mode": "selective",
        "reused": result.reused,
    }


@router.post("/threads/{thread_id}/attachments")
async def upload_attachment(thread_id:str,file:UploadFile=File(...),p:Principal=Depends(require_provisioned_principal),
                            settings:Settings=Depends(get_settings),db:Session=Depends(get_db)):
    if not settings.artifacts_enabled:
        raise HTTPException(403,"ARTIFACTS_DISABLED")
    _,member=thread_access(db,thread_id,p)
    if not member.can_upload_files: raise HTTPException(403,"UPLOAD_PERMISSION_REQUIRED")
    data=await file.read(settings.max_upload_bytes+1)
    if len(data)>settings.max_upload_bytes: raise HTTPException(413,"FILE_TOO_LARGE")
    digest=hashlib.sha256(data).hexdigest()
    safe,mime_type=_resolve_thread_document_upload_identity(file)
    key=f"{p.tenant_id}/{thread_id}/{digest}-{safe}"
    root=Path(settings.artifact_storage_path).resolve()
    target=(root/key).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise HTTPException(400,"STORAGE_PATH_INVALID")
    try:
        result=persist_attachment(
            db,
            tenant_id=p.tenant_id,
            thread_id=thread_id,
            uploaded_by=p.user_id,
            filename=safe,
            mime_type=mime_type,
            data=data,
            sha256=digest,
            storage_key=key,
            target=target,
            storage=build_blob_storage(settings),
        )
    except AttachmentIdentityConflict as exc:
        raise HTTPException(409,"ATTACHMENT_IDENTITY_CONFLICT") from exc
    except BlobStorageError as exc:
        raise HTTPException(503, str(exc)) from exc
    return {
        "id":result.attachment.id,
        "filename":result.attachment.filename,
        "sha256":result.attachment.sha256,
        "reused":result.reused,
    }


@router.get("/threads/{thread_id}/document-context")
def document_context_provenance(
    thread_id: str,
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    _, member = thread_access(db, thread_id, p)
    if not member.can_view_attachments:
        raise HTTPException(403, "ATTACHMENT_VIEW_PERMISSION_REQUIRED")
    bundle = build_document_context(
        db,
        settings=settings,
        tenant_id=p.tenant_id,
        thread_id=thread_id,
    )
    if bundle is None:
        return {
            "available": False,
            "sources": 0,
            "source_ids": [],
            "extraction_status": "none",
            "source_chars": 0,
            "provided_chars": 0,
            "per_source_truncated": False,
            "aggregate_truncated": False,
            "truncated": False,
            "context_version": "1.1",
            "source_provenance": [],
        }
    prov = bundle.provenance
    return {
        "available": prov.available,
        "sources": prov.sources,
        "source_ids": list(prov.source_ids),
        "extraction_status": prov.extraction_status,
        "source_chars": prov.source_chars,
        "provided_chars": prov.provided_chars,
        "per_source_truncated": prov.per_source_truncated,
        "aggregate_truncated": prov.aggregate_truncated,
        "truncated": prov.truncated,
        "context_version": prov.context_version,
        "source_provenance": [
            {
                "attachment_id": item.attachment_id,
                "filename": item.filename,
                "extraction_status": item.extraction_status,
                "source_chars": item.source_chars,
                "provided_chars": item.provided_chars,
                "truncated": item.truncated,
            }
            for item in prov.source_provenance
        ],
    }

@router.get("/artifacts/capabilities")
def artifact_capabilities(
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
):
    del p
    return artifact_capability_manifest(settings)


@router.get("/threads/{thread_id}/artifacts")
def list_artifacts(
    thread_id:str,
    p:Principal=Depends(require_provisioned_principal),
    db:Session=Depends(get_db),
):
    _,member=thread_access(db,thread_id,p)
    if not member.can_download_artifacts:
        raise HTTPException(403,"ARTIFACT_DOWNLOAD_PERMISSION_REQUIRED")
    rows=db.scalars(
        select(Artifact).where(
            Artifact.thread_id==thread_id,
            Artifact.tenant_id==p.tenant_id,
        ).order_by(Artifact.created_at.desc(), Artifact.id.desc())
    ).all()
    return [{
        "id":row.id,
        "filename":row.filename,
        "mime_type":row.mime_type,
        "sha256":row.sha256,
        "version":row.version,
        "created_at":row.created_at.isoformat() if row.created_at else None,
        "download_path":f"/api/v2/artifacts/{row.id}/download",
    } for row in rows]


@router.get("/artifacts/{artifact_id}/download")
def download_artifact(
    artifact_id:str,
    p:Principal=Depends(require_provisioned_principal),
    settings:Settings=Depends(get_settings),
    db:Session=Depends(get_db),
):
    row=db.get(Artifact,artifact_id)
    if not row or row.tenant_id != p.tenant_id:
        raise HTTPException(404,"ARTIFACT_NOT_FOUND")
    _,member=thread_access(db,row.thread_id,p)
    if not member.can_download_artifacts:
        raise HTTPException(403,"ARTIFACT_DOWNLOAD_PERMISSION_REQUIRED")
    try:
        raw = build_blob_storage(settings).get(row.storage_key)
    except BlobStorageError as exc:
        if str(exc) == "BLOB_NOT_FOUND":
            raise HTTPException(404,"ARTIFACT_FILE_NOT_FOUND") from exc
        raise HTTPException(503,"ARTIFACT_STORAGE_UNAVAILABLE") from exc
    if hashlib.sha256(raw).hexdigest() != row.sha256:
        raise HTTPException(409,"ARTIFACT_INTEGRITY_MISMATCH")
    safe_filename = row.filename.replace(chr(34), "")
    return Response(
        content=raw,
        media_type=row.mime_type,
        headers={
            "Cache-Control":"private, no-store",
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
        },
    )


@router.post("/evolution/proposals")
def create_proposal(payload:EvolutionProposalCreate,p:Principal=Depends(require_provisioned_admin),db:Session=Depends(get_db)):
    assert_provisioned(db,p)
    row=EvolutionProposal(tenant_id=p.tenant_id,created_by=p.user_id,**payload.model_dump())
    db.add(row); db.commit()
    return {"id":row.id,"status":row.status,"proposal_only":True,"human_approval_required":True,
            "write_executed":False,"commit_executed":False,"merge_executed":False,"deploy_executed":False}

@router.get("/admin/security/status")
def security_status(
    p: Principal = Depends(require_provisioned_principal),
    settings: Settings = Depends(get_settings),
):
    require_allowlisted_admin_principal(p, settings)
    return {
        "auth_mode": settings.auth_mode,
        "demo_headers_enabled": settings.demo_headers_enabled,
        "github_read_only": settings.github_read_only,
        "evolution_execution_allowed": settings.evolution_execution_allowed,
        "access_gate_enabled": settings.access_gate_enabled,
        "access_gate_code_hash_count": len([
            item for item in settings.access_gate_code_hashes.split(",") if item.strip()
        ]),
        "access_gate_tenant_configured": bool(settings.access_gate_tenant_id.strip()),
        "access_gate_signing_secret_configured": len(settings.access_gate_signing_secret) >= 32,
    }
