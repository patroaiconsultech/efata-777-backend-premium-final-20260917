
"""Contratos canônicos de runtime da ORKIO.

Esta camada é deliberadamente provider/catalog-neutral. Ela define
identidade, contexto, contribuições, eventos e invariantes; não executa
Team nem altera o roteador atual.
"""

from .contracts import (
    CanonicalMessage,
    CanonicalTurnContext,
    ContextContribution,
    ResponseEnvelope,
    RuntimeChannel,
    RuntimeRouteFamily,
)
from .events import RuntimeEvent, RuntimeEventType
from .identity import (
    OwnershipViolation,
    build_direct_turn_context,
    build_response_envelope,
    canonical_message,
    require_same_owner,
)
from .orchestration import (
    MAX_DELEGATION_DEPTH,
    AgentConsultRequest,
    OrchestrationContractError,
    OrchestrationRun,
    add_contribution,
)
from .realtime import (
    RealtimeIdentity,
    RealtimeIdentityError,
    realtime_identity_from_turn,
    validate_realtime_identity,
)

__all__ = [
    "CanonicalMessage",
    "CanonicalTurnContext",
    "ContextContribution",
    "ResponseEnvelope",
    "RuntimeChannel",
    "RuntimeRouteFamily",
    "RuntimeEvent",
    "RuntimeEventType",
    "OwnershipViolation",
    "build_direct_turn_context",
    "build_response_envelope",
    "canonical_message",
    "require_same_owner",
    "MAX_DELEGATION_DEPTH",
    "AgentConsultRequest",
    "OrchestrationContractError",
    "OrchestrationRun",
    "add_contribution",
    "RealtimeIdentity",
    "RealtimeIdentityError",
    "realtime_identity_from_turn",
    "validate_realtime_identity",
]
