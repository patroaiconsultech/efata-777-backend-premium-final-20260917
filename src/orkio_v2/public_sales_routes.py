"""B1.1 guided public sales: editorial-only, with gated distributed state.

No model, private identity, database, CRM, or paid provider is accessed.
Public environments fail closed unless shared Redis is explicitly approved
and reachable. This code candidate does not itself authorize public rollout.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .public_sales_redis import (
    SharedStoreUnavailable,
    create_shared_session,
    shared_store_gate_ready,
    transition_shared_session,
)

router = APIRouter(prefix="/api/v2/public/sales-sessions", tags=["public-sales-editorial"])

TTL_SECONDS = 30 * 60
ABSOLUTE_SECONDS = 45 * 60
PRIVACY_NOTICE_VERSION = "2026-10"
EDITORIAL_VERSION = "b1.1-editorial-2026-10-12"
MAX_SESSIONS = 1000
INTENTS = (
    "understand_platform", "shadow_ai_diagnostic", "governed_ai",
    "autonomous_sales", "implementation", "talk_to_specialist",
)
Intent = Literal[
    "understand_platform", "shadow_ai_diagnostic", "governed_ai",
    "autonomous_sales", "implementation", "talk_to_specialist",
]

# Each entry is human-reviewed editorial copy. No user message is interpolated.
# First answer selects a genuinely different follow-up question and recommendation.
_CATALOG = {
    "understand_platform": {
        "title": "Conhecer a plataforma",
        "question": "Qual objetivo trouxe você até a EFATA?",
        "branches": {
            "explore": ("Entender possibilidades", "Você busca orientação para qual cenário?",
                        ("operations", "Operação interna", "planning", "Planejamento")),
            "compare": ("Comparar soluções", "Qual critério pesa mais na sua comparação?",
                        ("governance", "Governança", "usability", "Facilidade de adoção")),
            "start": ("Iniciar um projeto", "Em que etapa sua empresa está?",
                      ("idea", "Definindo o caso de uso", "pilot", "Preparando piloto")),
        },
    },
    "shadow_ai_diagnostic": {
        "title": "Uso não supervisionado de IA",
        "question": "Existe uso de ferramentas de IA sem aprovação formal?",
        "branches": {
            "yes": ("Sim", "Que tipo de informação pode estar sendo compartilhada?",
                    ("sensitive", "Dados internos", "generic", "Conteúdo genérico")),
            "no": ("Não", "Como a empresa acompanha o uso autorizado?",
                   ("policy", "Política formal", "informal", "Orientações informais")),
            "unknown": ("Não sabemos", "Hoje há visibilidade das ferramentas utilizadas?",
                        ("inventory", "Há inventário", "none", "Ainda não há inventário")),
        },
    },
    "governed_ai": {
        "title": "Governança de IA",
        "question": "Qual controle precisa de mais atenção?",
        "branches": {
            "access": ("Acesso e permissões", "Como o acesso é controlado?",
                       ("defined", "Papéis definidos", "informal", "Sem papéis definidos")),
            "data": ("Proteção de dados", "Qual é o principal desafio com dados?",
                     ("classification", "Classificação", "sharing", "Compartilhamento")),
            "audit": ("Rastreabilidade", "Há registro das decisões automatizadas?",
                      ("yes", "Há registros", "no", "Ainda não")),
        },
    },
    "autonomous_sales": {
        "title": "Vendas com IA",
        "question": "Em qual etapa comercial você quer ganhar eficiência?",
        "branches": {
            "first": ("Primeiro contato", "Qual é o canal de entrada prioritário?",
                      ("site", "Site", "messaging", "Mensageria")),
            "qualify": ("Qualificação", "Quais critérios já são definidos?",
                        ("documented", "Critérios documentados", "informal", "Critérios informais")),
            "handoff": ("Passagem ao time", "Como o encaminhamento funciona hoje?",
                       ("crm", "CRM estruturado", "manual", "Processo manual")),
        },
    },
    "implementation": {
        "title": "Implantação responsável",
        "question": "Qual é a maturidade atual do projeto?",
        "branches": {
            "discovery": ("Descoberta", "Qual seria seu próximo passo?",
                          ("usecase", "Escolher caso de uso", "stakeholders", "Alinhar responsáveis")),
            "pilot": ("Piloto", "O que está definido no piloto?",
                      ("metrics", "Indicadores", "scope", "Escopo e limites")),
            "scale": ("Escala", "Qual desafio é mais urgente?",
                      ("governance", "Governança", "integration", "Integração")),
        },
    },
    "talk_to_specialist": {
        "title": "Preparar uma conversa especializada",
        "question": "Qual assunto deseja levar a um especialista?",
        "branches": {
            "strategy": ("Estratégia", "Qual decisão está em aberto?",
                         ("priority", "Prioridades", "investment", "Investimento")),
            "governance": ("Governança", "Qual aspecto está mais indefinido?",
                          ("policy", "Políticas", "roles", "Responsabilidades")),
            "technical": ("Integração técnica", "Qual parte exige análise?",
                         ("api", "APIs", "security", "Segurança")),
        },
    },
}
assert set(_CATALOG) == set(INTENTS)

class SessionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    language: Literal["pt-BR"] = "pt-BR"
    page_context: str = Field("landing", min_length=1, max_length=160)
    entry_intent: Intent = "understand_platform"
    audio_enabled: bool = False

class MessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: str | None = Field(None, max_length=80)
    message: str | None = Field(None, max_length=280)
    language: Literal["pt-BR"] = "pt-BR"
    intent_hint: Intent | None = None
    page_context: str = Field("landing", min_length=1, max_length=160)
    audio_enabled: bool = False

class Option(BaseModel):
    id: str
    label: str

class LeadCapture(BaseModel):
    eligible: bool = False
    reason: str = "integration_not_available"

class Experience(BaseModel):
    mode: Literal["editorial"] = "editorial"
    step: int
    total_steps: int = 3
    free_question_available: bool = False

class GuidedSummary(BaseModel):
    highlights: list[str]
    next_steps: list[str]
    notice: str = "Orientação inicial baseada nas suas escolhas; não equivale a auditoria técnica ou jurídica."

class MessageResponse(BaseModel):
    message: str
    intent: Intent
    stage: Literal["explain", "diagnose", "next_step"]
    suggested_actions: list[str]
    lead_capture: LeadCapture
    action_options: list[Option]
    experience: Experience
    summary: GuidedSummary | None = None

class SessionCreateResponse(BaseModel):
    session_id: str
    expires_at: str
    privacy_notice_version: str
    editorial_version: str
    opening: MessageResponse

_lock = threading.RLock()
_sessions: dict[str, dict] = {}
_limits: dict[str, deque[float]] = defaultdict(deque)

def reset_public_sales_state_for_tests() -> None:
    with _lock:
        _sessions.clear()
        _limits.clear()

def _enabled() -> None:
    # This guard is repeated in the route; middleware is the first line of defense.
    # Accidental enabling of a model feature must never change this zero-LLM slice.
    if os.getenv("PUBLIC_SALES_LLM_ENABLED", "false").lower() != "false":
        raise HTTPException(503, detail="PUBLIC_SALES_LLM_UNQUALIFIED")
    if os.getenv("PUBLIC_SALES_ENABLED", "false").lower() != "true":
        raise HTTPException(503, detail="PUBLIC_SALES_DISABLED")
    from .config import get_settings
    if get_settings().environment not in {"test", "development"} and not shared_store_gate_ready():
        raise HTTPException(503, detail="PUBLIC_SALES_SHARED_STORE_NOT_CONFIGURED")

def _check_limit(key: str, *, now: float, max_hits: int, seconds: int) -> None:
    bucket = _limits[key]
    while bucket and bucket[0] <= now - seconds:
        bucket.popleft()
    if len(bucket) >= max_hits:
        raise HTTPException(
            429, detail="PUBLIC_SALES_RATE_LIMITED",
            headers={"Retry-After": str(max(1, int(seconds - (now - bucket[0]))))},
        )
    bucket.append(now)

def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat()

def _current(session_id: str, now: float) -> dict:
    session = _sessions.get(session_id)
    if session is None:
        raise HTTPException(404, detail="PUBLIC_SALES_SESSION_NOT_FOUND")
    if now >= session["expires"] or now >= session["absolute"]:
        _sessions.pop(session_id, None)
        raise HTTPException(410, detail="PUBLIC_SALES_SESSION_EXPIRED")
    return session

def _opening(intent: Intent) -> MessageResponse:
    entry = _CATALOG[intent]
    options = [Option(id=key, label=item[0]) for key, item in entry["branches"].items()]
    return MessageResponse(
        message=entry["question"], intent=intent, stage="diagnose",
        suggested_actions=[item.label for item in options],
        action_options=options,
        lead_capture=LeadCapture(), experience=Experience(step=1),
    )

def _followup(intent: Intent, selected: str) -> MessageResponse:
    branch = _CATALOG[intent]["branches"][selected]
    options = [Option(id=branch[2][0], label=branch[2][1]),
               Option(id=branch[2][2], label=branch[2][3])]
    return MessageResponse(
        message=branch[1], intent=intent, stage="diagnose",
        suggested_actions=[item.label for item in options],
        action_options=options,
        lead_capture=LeadCapture(), experience=Experience(step=2),
    )

def _result(intent: Intent, first: str, second: str) -> MessageResponse:
    entry = _CATALOG[intent]
    branch = entry["branches"][first]
    answers = {branch[2][0]: branch[2][1], branch[2][2]: branch[2][3]}
    # Every sentence derives from approved copy and validated option IDs.
    summary = GuidedSummary(
        highlights=[
            f"Tema escolhido: {entry['title']}.",
            f"Situação indicada: {branch[0]}.",
            f"Contexto adicional: {answers[second]}.",
        ],
        next_steps=[
            f"Documentar o cenário relacionado a {branch[0].lower()}.",
            f"Verificar controles e responsabilidades ligados a {answers[second].lower()}.",
            "Definir um próximo passo pequeno, com responsável e critério de sucesso.",
        ],
    )
    return MessageResponse(
        message="Com base nas suas escolhas, esta é uma orientação inicial que você pode copiar e revisar.",
        intent=intent, stage="next_step", suggested_actions=[],
        action_options=[], lead_capture=LeadCapture(),
        experience=Experience(step=3), summary=summary,
    )

# Approved editorial action IDs, not browser-supplied state.
_SHARED_ACTION_CATALOG = {
    intent: {
        key: [branch[2][0], branch[2][2]]
        for key, branch in catalog["branches"].items()
    }
    for intent, catalog in _CATALOG.items()
}

@router.post("", status_code=201, response_model=SessionCreateResponse)
async def create_session(payload: SessionCreateRequest, request: Request) -> SessionCreateResponse:
    _enabled()
    now = time.time()
    client_ip = getattr(request.state, "public_sales_client_ip", "unknown")
    from .config import get_settings
    if get_settings().environment not in {"test", "development"}:
        try:
            token, expires_ms = await create_shared_session(intent=payload.entry_intent, client_ip=client_ip)
        except SharedStoreUnavailable as exc:
            raise HTTPException(503, detail="PUBLIC_SALES_SHARED_STORE_UNAVAILABLE") from exc
        if token == "rate_limited":
            raise HTTPException(429, detail="PUBLIC_SALES_RATE_LIMITED", headers={"Retry-After": "60"})
        if token == "capacity":
            raise HTTPException(503, detail="PUBLIC_SALES_CAPACITY_REACHED")
        return SessionCreateResponse(
            session_id=token, expires_at=_iso(expires_ms / 1000),
            privacy_notice_version=PRIVACY_NOTICE_VERSION,
            editorial_version=EDITORIAL_VERSION, opening=_opening(payload.entry_intent),
        )
    with _lock:
        _check_limit(f"create:{client_ip}", now=now, max_hits=8, seconds=600)
        for key, session in list(_sessions.items()):
            if session["expires"] <= now or session["absolute"] <= now:
                del _sessions[key]
        if len(_sessions) >= MAX_SESSIONS:
            raise HTTPException(503, detail="PUBLIC_SALES_CAPACITY_REACHED")
        token = secrets.token_urlsafe(32)
        _sessions[token] = {
            "intent": payload.entry_intent, "step": 0, "first": None,
            "expires": now + TTL_SECONDS, "absolute": now + ABSOLUTE_SECONDS,
        }
    return SessionCreateResponse(
        session_id=token, expires_at=_iso(now + TTL_SECONDS),
        privacy_notice_version=PRIVACY_NOTICE_VERSION,
        editorial_version=EDITORIAL_VERSION, opening=_opening(payload.entry_intent),
    )

@router.post("/{session_id}/messages", response_model=MessageResponse)
async def send_message(session_id: str, payload: MessageRequest, request: Request) -> MessageResponse:
    _enabled()
    if payload.message is not None or not payload.action_id:
        # No disguised free text / model calls in the editorial-only gate.
        raise HTTPException(422, detail="PUBLIC_SALES_ACTION_REQUIRED")
    from .config import get_settings
    if get_settings().environment not in {"test", "development"}:
        client_ip = getattr(request.state, "public_sales_client_ip", "unknown")
        try:
            outcome, intent, first, _ = await transition_shared_session(
                token=session_id, action_id=payload.action_id,
                intent_hint=payload.intent_hint, client_ip=client_ip,
                catalog=_SHARED_ACTION_CATALOG,
            )
        except SharedStoreUnavailable as exc:
            raise HTTPException(503, detail="PUBLIC_SALES_SHARED_STORE_UNAVAILABLE") from exc
        errors = {
            "not_found": (404,"PUBLIC_SALES_SESSION_NOT_FOUND"),
            "expired": (410,"PUBLIC_SALES_SESSION_EXPIRED"),
            "completed": (409,"PUBLIC_SALES_ALREADY_COMPLETED"),
            "locked": (409,"PUBLIC_SALES_INTENT_LOCKED"),
            "invalid": (409,"PUBLIC_SALES_ACTION_INVALID"),
            "rate_limited": (429,"PUBLIC_SALES_RATE_LIMITED"),
        }
        if outcome in errors:
            status, detail = errors[outcome]
            headers = {"Retry-After": "60"} if status == 429 else None
            raise HTTPException(status, detail=detail, headers=headers)
        if outcome == "followup":
            return _followup(intent, first)
        if outcome == "result":
            return _result(intent, first, payload.action_id)
        raise HTTPException(503, detail="PUBLIC_SALES_SHARED_STORE_UNAVAILABLE")
    now = time.time()
    with _lock:
        item = _current(session_id, now)
        _check_limit(f"message:{session_id}", now=now, max_hits=15, seconds=60)
        intent = item["intent"]
        if payload.intent_hint is not None and payload.intent_hint != intent:
            raise HTTPException(409, detail="PUBLIC_SALES_INTENT_LOCKED")
        if item["step"] == 0:
            if payload.action_id not in _CATALOG[intent]["branches"]:
                raise HTTPException(409, detail="PUBLIC_SALES_ACTION_INVALID")
            item["first"] = payload.action_id
            item["step"] = 1
            response = _followup(intent, payload.action_id)
        elif item["step"] == 1:
            branch = _CATALOG[intent]["branches"][item["first"]]
            if payload.action_id not in {branch[2][0], branch[2][2]}:
                raise HTTPException(409, detail="PUBLIC_SALES_ACTION_INVALID")
            item["step"] = 2
            response = _result(intent, item["first"], payload.action_id)
        else:
            raise HTTPException(409, detail="PUBLIC_SALES_ALREADY_COMPLETED")
        item["expires"] = min(now + TTL_SECONDS, item["absolute"])
        return response

@router.post("/{session_id}/handoff")
def unavailable_handoff(session_id: str) -> None:
    _enabled()
    # No contact collection or misleading 202 until a genuine human destination is proven.
    raise HTTPException(503, detail="PUBLIC_SALES_HUMAN_HANDOFF_UNAVAILABLE")
