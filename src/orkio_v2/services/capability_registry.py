from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol

from .capability_policy import CapabilityPolicy


CAPABILITY_VERSION = "1.0.0"
AUDIT_FILE_INSPECT = f"audit.file.inspect@{CAPABILITY_VERSION}"
AUDIT_ARCHIVE_INSPECT = f"audit.archive.inspect@{CAPABILITY_VERSION}"
AUDIT_RUNTIME_FILE_SHA256 = f"audit.runtime.file_sha256@{CAPABILITY_VERSION}"
AUDIT_RUNTIME_SEARCH_MARKER = f"audit.runtime.search_marker@{CAPABILITY_VERSION}"

FROZEN_AUDIT_CAPABILITY_IDS = (
    AUDIT_FILE_INSPECT,
    AUDIT_ARCHIVE_INSPECT,
    AUDIT_RUNTIME_FILE_SHA256,
    AUDIT_RUNTIME_SEARCH_MARKER,
)


class RateLimitCheck(Protocol):
    def __call__(
        self,
        *,
        capability_id: str,
        user_id: str,
        tenant_id: str,
        resolved_agent_id: str,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class CapabilitySpec:
    capability_id: str
    capability_version: str
    description: str
    risk_level: str
    runtime: str
    network: bool
    write: bool
    timeout_seconds: float
    max_output_bytes: int
    enabled: bool


@dataclass(frozen=True, slots=True)
class TrustedCapabilityContext:
    """Server-owned authorization context.

    `resolved_agent_id` is the authorization subject. No request payload field is
    accepted here as a substitute for the canonical server-resolved identity.
    """

    user_id: str
    tenant_id: str
    environment: str
    requested_agent_id: str | None
    resolved_agent_id: str
    turn_owner_agent_id: str | None
    privileged_user: bool


@dataclass(frozen=True, slots=True)
class CapabilityDecision:
    capability_id: str
    allowed: bool
    reason: str
    authorization_subject: str


class CapabilityRegistry:
    def __init__(
        self,
        *,
        policy: CapabilityPolicy,
        rate_limit_check: RateLimitCheck | None = None,
    ) -> None:
        self._policy = policy
        self._rate_limit_check = rate_limit_check
        runtime_master = bool(
            policy.audit_evidence_capabilities_enabled
            and policy.audit_runtime_inspect_enabled
        )
        self._specs: Mapping[str, CapabilitySpec] = {
            AUDIT_FILE_INSPECT: CapabilitySpec(
                capability_id=AUDIT_FILE_INSPECT,
                capability_version=CAPABILITY_VERSION,
                description="Bounded read-only inspection of a server-approved file.",
                risk_level="HIGH",
                runtime="server",
                network=False,
                write=False,
                timeout_seconds=policy.audit_timeout_seconds,
                max_output_bytes=policy.audit_max_output_bytes,
                enabled=bool(
                    policy.audit_evidence_capabilities_enabled
                    and policy.audit_file_inspect_enabled
                ),
            ),
            AUDIT_ARCHIVE_INSPECT: CapabilitySpec(
                capability_id=AUDIT_ARCHIVE_INSPECT,
                capability_version=CAPABILITY_VERSION,
                description="Bounded read-only ZIP inspection from a verified file handle.",
                risk_level="HIGH",
                runtime="server",
                network=False,
                write=False,
                timeout_seconds=policy.audit_timeout_seconds,
                max_output_bytes=policy.audit_max_output_bytes,
                enabled=bool(
                    policy.audit_evidence_capabilities_enabled
                    and policy.audit_archive_inspect_enabled
                ),
            ),
            AUDIT_RUNTIME_FILE_SHA256: CapabilitySpec(
                capability_id=AUDIT_RUNTIME_FILE_SHA256,
                capability_version=CAPABILITY_VERSION,
                description="SHA-256 hashing of an allowlisted runtime module.",
                risk_level="HIGH",
                runtime="server",
                network=False,
                write=False,
                timeout_seconds=policy.audit_timeout_seconds,
                max_output_bytes=policy.audit_max_output_bytes,
                enabled=bool(
                    runtime_master and policy.audit_runtime_file_sha256_enabled
                ),
            ),
            AUDIT_RUNTIME_SEARCH_MARKER: CapabilitySpec(
                capability_id=AUDIT_RUNTIME_SEARCH_MARKER,
                capability_version=CAPABILITY_VERSION,
                description="Bounded literal-marker search in an allowlisted runtime module.",
                risk_level="HIGH",
                runtime="server",
                network=False,
                write=False,
                timeout_seconds=policy.audit_timeout_seconds,
                max_output_bytes=policy.audit_max_output_bytes,
                enabled=bool(
                    runtime_master and policy.audit_runtime_search_marker_enabled
                ),
            ),
        }

    def get(self, capability_id: str) -> CapabilitySpec:
        try:
            return self._specs[capability_id]
        except KeyError as exc:
            raise KeyError("AUDIT_CAPABILITY_UNKNOWN") from exc

    def manifest(self) -> list[dict[str, object]]:
        return [
            {
                "capability_id": spec.capability_id,
                "capability_version": spec.capability_version,
                "description": spec.description,
                "risk_level": spec.risk_level,
                "runtime": spec.runtime,
                "network": spec.network,
                "write": spec.write,
                "timeout_seconds": spec.timeout_seconds,
                "max_output_bytes": spec.max_output_bytes,
                "enabled": spec.enabled,
            }
            for spec in self._specs.values()
        ]

    def authorize(
        self,
        capability_id: str,
        *,
        context: TrustedCapabilityContext,
        exact_agent_binding: bool = True,
    ) -> CapabilityDecision:
        spec = self.get(capability_id)
        subject = context.resolved_agent_id.strip().lower()

        if not spec.enabled:
            return CapabilityDecision(
                capability_id, False, "AUDIT_CAPABILITY_DISABLED", subject
            )
        if not context.privileged_user:
            return CapabilityDecision(
                capability_id, False, "AUDIT_CAPABILITY_USER_DENIED", subject
            )
        if not subject:
            return CapabilityDecision(
                capability_id, False, "AUDIT_CAPABILITY_AGENT_DENIED", subject
            )

        allowed_agents = set(self._policy.audit_allowed_agent_ids)
        if subject not in allowed_agents:
            return CapabilityDecision(
                capability_id, False, "AUDIT_CAPABILITY_AGENT_DENIED", subject
            )

        if exact_agent_binding and context.requested_agent_id:
            requested = context.requested_agent_id.strip().lower()
            if requested != subject:
                return CapabilityDecision(
                    capability_id,
                    False,
                    "AUDIT_CAPABILITY_AGENT_IDENTITY_MISMATCH",
                    subject,
                )

        tenant = context.tenant_id.strip().lower()
        if not tenant or tenant not in set(self._policy.audit_allowed_tenant_ids):
            return CapabilityDecision(
                capability_id, False, "AUDIT_CAPABILITY_TENANT_DENIED", subject
            )

        environment = context.environment.strip().lower()
        if (
            not environment
            or environment not in set(self._policy.audit_allowed_environments)
        ):
            return CapabilityDecision(
                capability_id, False, "AUDIT_CAPABILITY_ENVIRONMENT_DENIED", subject
            )

        if self._rate_limit_check is None:
            return CapabilityDecision(
                capability_id, False, "AUDIT_RATE_LIMITER_UNAVAILABLE", subject
            )
        if not self._rate_limit_check(
            capability_id=capability_id,
            user_id=context.user_id,
            tenant_id=context.tenant_id,
            resolved_agent_id=context.resolved_agent_id,
        ):
            return CapabilityDecision(
                capability_id, False, "AUDIT_REQUEST_RATE_LIMITED", subject
            )

        return CapabilityDecision(capability_id, True, "ALLOW", subject)
