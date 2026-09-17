from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Callable

from .audit_archive_adapter import AuditArchiveAdapter
from .audit_archive_source_resolver import AuditArchiveSourceError, AuditArchiveSourceResolver
from .audit_capability_guard import AuditCapabilityGuard
from .audit_evidence import build_evidence_envelope
from .audit_evidence_repository import AppendEvidenceResult, append_evidence
from .audit_file_adapter import AuditFileAdapter
from .audit_invocation_contracts import (
    AUDIT_CANONICAL_AGENT_ID,
    AUDIT_GOVERNANCE_MODE,
    RUNTIME_MODULE_ALLOWLIST,
)
from .audit_invocation_directive import (
    AuditDirective,
    AuditDirectiveError,
    looks_like_audit_directive,
    parse_audit_directive,
)
from .ao01_audit_trace import emit_audit_trace
from .audit_invocation_rate_limit import (
    AuditDirectiveAbuseLimiter,
    AuditRateLimitError,
    LedgerAuditRateLimitCheck,
)
from .audit_runtime_adapter import AuditRuntimeAdapter
from .capability_policy import CapabilityPolicy
from .capability_registry import (
    CapabilityDecision,
    CapabilityRegistry,
    TrustedCapabilityContext,
)
from .target_resolver import TargetResolutionError, resolve_target
from ..runtime.contracts import CanonicalTurnContext, RuntimeChannel, RuntimeRouteFamily


class AuditInvocationError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        http_status: int = 422,
        audit_reference: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.http_status = http_status
        self.audit_reference = audit_reference


_AUDIT_REQUEST_BINDING_CONTRACT = "ORKIO-AUDIT-REQUEST-BINDING-1"
_DIGEST_BOUND_ARGUMENTS = frozenset({"artifact_id", "member_name", "marker"})


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _build_request_binding(
    directive: AuditDirective,
    *,
    turn: CanonicalTurnContext,
) -> dict[str, Any]:
    canonical_payload = {
        "version": directive.version,
        "operation": directive.operation,
        **directive.arguments,
    }
    canonical_bytes = json.dumps(
        canonical_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    arguments: dict[str, Any] = {}
    for name in sorted(directive.arguments):
        value = directive.arguments[name]
        if name in _DIGEST_BOUND_ARGUMENTS and isinstance(value, str):
            arguments[name] = {
                "binding": "sha256",
                "sha256": _sha256_text(value),
                "source": "current_parsed_directive",
            }
        else:
            arguments[name] = {
                "binding": "literal",
                "value": value,
                "source": "current_parsed_directive",
            }

    return {
        "contract": _AUDIT_REQUEST_BINDING_CONTRACT,
        "canonicalization": "json-sort-keys-v1",
        "directive_sha256": hashlib.sha256(canonical_bytes).hexdigest(),
        "source": "current_parsed_directive_and_canonical_turn",
        "version": directive.version,
        "operation": directive.operation,
        "turn": {
            "request_id": turn.request_id,
            "execution_id": turn.execution_id,
            "thread_id": turn.thread_id,
            "tenant_id": turn.tenant_id,
            "requested_agent": turn.requested_target,
            "resolved_agent": turn.resolved_agent_id,
            "turn_owner": turn.turn_owner_agent_id,
            "route_family": turn.route_family.value,
            "channel": turn.channel.value,
            "ownership_locked": turn.ownership_locked,
        },
        "arguments": arguments,
    }


def _verify_request_result_binding(
    *,
    directive: AuditDirective,
    request_binding: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    checks: dict[str, Any] = {}

    if directive.operation in {
        "runtime.file_sha256",
        "runtime.search_marker",
    }:
        expected_module = (
            request_binding.get("arguments", {})
            .get("module_id", {})
            .get("value")
        )
        actual_module = result.get("module_id")
        if (
            not isinstance(expected_module, str)
            or not isinstance(actual_module, str)
            or not hmac.compare_digest(expected_module, actual_module)
        ):
            raise AuditInvocationError(
                "AUDIT_REQUEST_RESULT_BINDING_MISMATCH",
                http_status=500,
            )
        checks["module_id_matches_request"] = True

    if directive.operation in {
        "file.find_literal_marker",
        "runtime.search_marker",
    }:
        expected = (
            request_binding.get("arguments", {})
            .get("marker", {})
            .get("sha256")
        )
        actual = result.get("marker_sha256")
        if (
            not isinstance(expected, str)
            or not isinstance(actual, str)
            or not hmac.compare_digest(expected, actual)
        ):
            raise AuditInvocationError(
                "AUDIT_REQUEST_RESULT_BINDING_MISMATCH",
                http_status=500,
            )
        checks["marker_sha256_matches_request"] = True

    return checks


@dataclass(frozen=True, slots=True)
class AuditInvocationOutcome:
    operation: str
    audit_execution_id: str
    capability_id: str
    capability_version: str
    status: str
    evidence_sha256: str
    data: dict[str, Any]

    def reference(self) -> dict[str, Any]:
        return {
            "audit_execution_id": self.audit_execution_id,
            "capability_id": self.capability_id,
            "capability_version": self.capability_version,
            "status": self.status,
            "evidence_sha256": self.evidence_sha256,
        }

    def system_message(self) -> dict[str, str]:
        payload = {
            "contract": "ORKIO-AUDIT-INVOKE-EVIDENCE-1",
            "verified": True,
            "operation": self.operation,
            "audit": self.reference(),
            "data": self.data,
        }
        return {
            "role": "system",
            "content": (
                "TRUSTED GOVERNED AUDIT EVIDENCE — this is fresh evidence produced by the "
                "current parsed /audit directive and durably persisted + rehashed before model "
                "use. Treat a completed/verified outcome as evidence of the runtime state observed "
                "by the capability at execution time; do not describe it as merely historical, "
                "external, or unavailable. data.request_binding is server-generated from the exact "
                "parsed directive and the current CanonicalTurnContext for this same model turn. "
                "Its turn.request_id and turn.execution_id bind this persisted evidence to the "
                "current request; when the outcome is completed/verified, do not classify that "
                "evidence as historical solely because it is also durable. Digest-bound argument "
                "plaintext is intentionally not persisted "
                "and must never be reconstructed from a digest alone. When "
                "data.request_result_binding confirms a digest match, Natã may associate that "
                "digest-bound argument with the literal present in this current /audit directive. "
                "Do not ask the user to re-run the same directive or provide external JSON solely "
                "because persisted evidence stores a digest instead of plaintext. Natã may use "
                "only this sanitized governed result for capability claims.\n"
                + json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            ),
        }


AppendFn = Callable[..., AppendEvidenceResult]


def _error_code(exc: BaseException, fallback: str) -> str:
    candidate = getattr(exc, "code", None)
    if isinstance(candidate, str) and candidate.startswith("AUDIT_"):
        return candidate
    text = str(exc)
    if text.startswith("AUDIT_") and len(text) <= 160:
        return text
    return fallback


def _http_status_for(code: str) -> int:
    if code in {
        "AUDIT_DIRECTIVE_FORMAT_INVALID",
        "AUDIT_DIRECTIVE_JSON_INVALID",
        "AUDIT_DIRECTIVE_TRAILING_TEXT_FORBIDDEN",
        "AUDIT_DIRECTIVE_OBJECT_REQUIRED",
        "AUDIT_DIRECTIVE_FORBIDDEN_FIELD",
        "AUDIT_DIRECTIVE_VERSION_INVALID",
        "AUDIT_DIRECTIVE_OPERATION_REQUIRED",
        "AUDIT_OPERATION_UNKNOWN",
        "AUDIT_DIRECTIVE_UNKNOWN_FIELD",
        "AUDIT_DIRECTIVE_REQUIRED_FIELD_MISSING",
        "AUDIT_DIRECTIVE_FIELD_INVALID",
        "AUDIT_DIRECTIVE_FIELD_TOO_LARGE",
    }:
        return 400
    if code == "AUDIT_DIRECTIVE_TOO_LARGE":
        return 413
    if code in {"AUDIT_DIRECTIVE_RATE_LIMITED", "AUDIT_REQUEST_RATE_LIMITED"}:
        return 429
    if code in {
        "AUDIT_RATE_LIMITER_UNAVAILABLE",
        "AUDIT_EVIDENCE_PERSISTENCE_FAILED",
        "AUDIT_EVIDENCE_PERSISTENCE_INTEGRITY_ERROR",
        "AUDIT_EVIDENCE_PERSISTENCE_INTEGRITY_MISMATCH",
    }:
        return 503
    if code == "AUDIT_REQUEST_RESULT_BINDING_MISMATCH":
        return 500
    if code == "AUDIT_REQUEST_TIMEOUT":
        return 504
    if code in {"AUDIT_ARCHIVE_NOT_FOUND"}:
        return 404
    if code in {
        "AUDIT_GOVERNED_INVOCATION_DISABLED",
        "AUDIT_INVOCATION_ROUTE_DENIED",
        "AUDIT_INVOCATION_CHANNEL_DENIED",
        "AUDIT_INVOCATION_OWNERSHIP_REQUIRED",
        "AUDIT_INVOCATION_AGENT_DENIED",
        "AUDIT_INVOCATION_AGENT_IDENTITY_MISMATCH",
        "AUDIT_INVOCATION_EXECUTION_DENIED",
        "AUDIT_INVOCATION_EXTERNAL_WRITE_FORBIDDEN",
        "AUDIT_CAPABILITY_DISABLED",
        "AUDIT_CAPABILITY_USER_DENIED",
        "AUDIT_CAPABILITY_AGENT_DENIED",
        "AUDIT_CAPABILITY_AGENT_IDENTITY_MISMATCH",
        "AUDIT_CAPABILITY_TENANT_DENIED",
        "AUDIT_CAPABILITY_ENVIRONMENT_DENIED",
    }:
        return 403
    return 422


class GovernedAuditInvocationService:
    """V1 governed bridge: explicit Natã directive -> one read-only capability -> ledger."""

    def __init__(
        self,
        *,
        session_factory,
        settings,
        project_root: Path,
        policy: CapabilityPolicy | None = None,
        directive_abuse_limiter: AuditDirectiveAbuseLimiter | None = None,
        append_fn: AppendFn = append_evidence,
        runtime_module_allowlist=None,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings
        self._project_root = Path(project_root)
        self._policy = policy or CapabilityPolicy.from_env()
        self._directive_abuse_limiter = (
            directive_abuse_limiter or AuditDirectiveAbuseLimiter(
                window_seconds=60,
                per_user_limit=self._policy.audit_directive_user_rate_limit,
            )
        )
        self._append_fn = append_fn
        self._runtime_module_allowlist = dict(
            runtime_module_allowlist or RUNTIME_MODULE_ALLOWLIST
        )
        self._rate_check = LedgerAuditRateLimitCheck(
            session_factory=session_factory,
            window_seconds=self._policy.audit_rate_limit_window_seconds,
            user_limit=self._policy.audit_user_rate_limit_per_window,
            tenant_limit=self._policy.audit_tenant_rate_limit_per_window,
        )
        self._registry = CapabilityRegistry(
            policy=self._policy,
            rate_limit_check=self._rate_check,
        )
        self._guard = AuditCapabilityGuard()

    @staticmethod
    def _requested_canonical_agent_id(turn: CanonicalTurnContext) -> str | None:
        try:
            return resolve_target(turn.requested_target).agent_id
        except TargetResolutionError:
            return None

    def _deployment_id(self) -> str:
        for value in (
            getattr(self._settings, "railway_deployment_id", None),
            getattr(self._settings, "release_sha", None),
            getattr(self._settings, "platform_release_sha", None),
        ):
            if value and str(value).strip():
                return str(value).strip()
        return "unknown"

    def _trace(
        self,
        stage: str,
        *,
        turn: CanonicalTurnContext,
        directive: AuditDirective | None = None,
        audit_execution_id: str | None = None,
        status: str | None = None,
        error_code: str | None = None,
        repository_verified_on_return: bool | None = None,
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
            capability_id=directive.spec.capability_id if directive is not None else None,
            operation=directive.operation if directive is not None else None,
            deployment_id=self._deployment_id(),
            build_sha=str(getattr(self._settings, "release_sha", "unknown") or "unknown"),
            status=status,
            error_code=error_code,
            repository_verified_on_return=repository_verified_on_return,
        )

    def _evidence_root(self, directive: AuditDirective) -> str | None:
        if directive.operation.startswith(("file.", "archive.")):
            return "artifact"
        if directive.operation.startswith("runtime."):
            return "runtime"
        return None

    def _persist_evidence(
        self,
        *,
        turn: CanonicalTurnContext,
        requested_canonical_agent_id: str | None,
        directive: AuditDirective,
        capability_decision: str,
        capability_decision_reason: str,
        status: str,
        sanitized: bool,
        read_executed: bool,
        data: dict[str, Any] | None,
        error_code: str | None,
    ) -> tuple[dict[str, Any], AppendEvidenceResult]:
        started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        finished_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        envelope = build_evidence_envelope(
            request_id=turn.request_id,
            execution_id=turn.execution_id,
            tenant_id=turn.tenant_id,
            user_id=turn.user_id,
            capability_id=directive.spec.capability_id,
            capability_version=self._registry.get(
                directive.spec.capability_id
            ).capability_version,
            environment=str(getattr(self._settings, "environment", "unknown")),
            deployment_id=self._deployment_id(),
            requested_agent_id=requested_canonical_agent_id,
            resolved_agent_id=turn.resolved_agent_id,
            turn_owner_agent_id=turn.turn_owner_agent_id,
            capability_decision=capability_decision,
            capability_decision_reason=capability_decision_reason,
            status=status,
            sanitized=sanitized,
            read_executed=read_executed,
            write_executed=False,
            migration_executed=False,
            deploy_executed=False,
            human_approval_required=True,
            started_at=started_at,
            finished_at=finished_at,
            artifact_id=(
                str(directive.arguments["artifact_id"])
                if "artifact_id" in directive.arguments
                else None
            ),
            root_id=self._evidence_root(directive),
            data=data,
            error_code=error_code,
        )
        self._trace(
            "evidence_persist_started",
            turn=turn,
            directive=directive,
            audit_execution_id=envelope.audit_execution_id,
            status=status,
            error_code=error_code,
        )
        try:
            result = self._append_fn(
                envelope,
                session_factory=self._session_factory,
            )
        except Exception as exc:
            code = _error_code(exc, "AUDIT_EVIDENCE_PERSISTENCE_FAILED")
            self._trace(
                "evidence_persist_failed",
                turn=turn,
                directive=directive,
                audit_execution_id=envelope.audit_execution_id,
                status="failed",
                error_code=code,
            )
            raise AuditInvocationError(
                code,
                http_status=_http_status_for(code),
            ) from exc
        self._trace(
            "evidence_repository_returned",
            turn=turn,
            directive=directive,
            audit_execution_id=envelope.audit_execution_id,
            status=status,
            error_code=error_code,
            repository_verified_on_return=(self._append_fn is append_evidence),
        )
        return envelope.to_dict(), result

    def _deny(
        self,
        *,
        turn: CanonicalTurnContext,
        requested_canonical_agent_id: str | None,
        directive: AuditDirective,
        reason: str,
        public_reason: str | None = None,
    ) -> None:
        if not turn.internal_persistence_allowed:
            raise AuditInvocationError(
                "AUDIT_INVOCATION_INTERNAL_PERSISTENCE_REQUIRED",
                http_status=403,
            )
        envelope, append_result = self._persist_evidence(
            turn=turn,
            requested_canonical_agent_id=requested_canonical_agent_id,
            directive=directive,
            capability_decision="DENY",
            capability_decision_reason=reason,
            status="denied",
            sanitized=True,
            read_executed=False,
            data={"operation": directive.operation},
            error_code=reason,
        )
        ref = {
            "audit_execution_id": envelope["audit_execution_id"],
            "capability_id": envelope["capability_id"],
            "capability_version": envelope["capability_version"],
            "status": "denied",
            "evidence_sha256": append_result.evidence_sha256,
        }
        public_reason = public_reason or reason
        raise AuditInvocationError(
            public_reason,
            http_status=_http_status_for(public_reason),
            audit_reference=ref,
        )

    def _preflight_reason(
        self,
        *,
        turn: CanonicalTurnContext,
        requested_canonical_agent_id: str | None,
    ) -> str | None:
        if not self._policy.audit_governed_invocation_enabled:
            return "AUDIT_GOVERNED_INVOCATION_DISABLED"
        if turn.route_family != RuntimeRouteFamily.DIRECT_AGENT:
            return "AUDIT_INVOCATION_ROUTE_DENIED"
        if turn.channel not in {RuntimeChannel.CHAT_JSON, RuntimeChannel.CHAT_SSE}:
            return "AUDIT_INVOCATION_CHANNEL_DENIED"
        if not turn.ownership_locked:
            return "AUDIT_INVOCATION_OWNERSHIP_REQUIRED"
        if (
            turn.resolved_agent_id != AUDIT_CANONICAL_AGENT_ID
            or turn.turn_owner_agent_id != AUDIT_CANONICAL_AGENT_ID
        ):
            return "AUDIT_INVOCATION_AGENT_DENIED"
        if requested_canonical_agent_id != AUDIT_CANONICAL_AGENT_ID:
            return "AUDIT_INVOCATION_AGENT_IDENTITY_MISMATCH"
        if not turn.execution_allowed:
            return "AUDIT_INVOCATION_EXECUTION_DENIED"
        if turn.external_write_allowed:
            return "AUDIT_INVOCATION_EXTERNAL_WRITE_FORBIDDEN"
        return None

    def _trusted_context(
        self,
        *,
        turn: CanonicalTurnContext,
        requested_canonical_agent_id: str | None,
        privileged_user: bool,
    ) -> TrustedCapabilityContext:
        return TrustedCapabilityContext(
            user_id=turn.user_id,
            tenant_id=turn.tenant_id,
            environment=str(getattr(self._settings, "environment", "unknown")),
            requested_agent_id=requested_canonical_agent_id,
            resolved_agent_id=turn.resolved_agent_id,
            turn_owner_agent_id=turn.turn_owner_agent_id,
            privileged_user=privileged_user,
        )

    def _authorize(
        self,
        *,
        directive: AuditDirective,
        turn: CanonicalTurnContext,
        requested_canonical_agent_id: str | None,
        privileged_user: bool,
    ) -> CapabilityDecision:
        try:
            return self._registry.authorize(
                directive.spec.capability_id,
                context=self._trusted_context(
                    turn=turn,
                    requested_canonical_agent_id=requested_canonical_agent_id,
                    privileged_user=privileged_user,
                ),
                exact_agent_binding=True,
            )
        except AuditRateLimitError:
            return CapabilityDecision(
                directive.spec.capability_id,
                False,
                "AUDIT_RATE_LIMITER_UNAVAILABLE",
                turn.resolved_agent_id,
            )

    def _operation(self, directive: AuditDirective, *, tenant_id: str):
        args = dict(directive.arguments)

        if directive.operation.startswith("file."):
            artifact_id = str(args["artifact_id"])

            def file_operation():
                with self._session_factory() as lookup_db:
                    resolver = AuditArchiveSourceResolver.from_local_runtime(
                        db=lookup_db,
                        settings=self._settings,
                    )
                    with resolver.resolve_artifact(
                        artifact_id=artifact_id,
                        tenant_id=tenant_id,
                    ) as verified:
                        adapter = AuditFileAdapter()
                        if directive.operation == "file.metadata":
                            return adapter.file_metadata(verified)
                        if directive.operation == "file.read_text":
                            return adapter.read_text(
                                verified,
                                offset=int(args.get("offset", 0)),
                                max_bytes=int(args.get("max_bytes", 16_000)),
                            )
                        if directive.operation == "file.find_literal_marker":
                            return adapter.find_literal_marker(
                                verified,
                                str(args["marker"]),
                                max_scan_bytes=args.get("max_scan_bytes"),
                                max_matches=int(args.get("max_matches", 256)),
                            )
                raise AuditInvocationError("AUDIT_OPERATION_UNKNOWN")

            return file_operation

        if directive.operation.startswith("archive."):
            artifact_id = str(args["artifact_id"])

            def archive_operation():
                with self._session_factory() as lookup_db:
                    resolver = AuditArchiveSourceResolver.from_local_runtime(
                        db=lookup_db,
                        settings=self._settings,
                    )
                    with resolver.resolve_artifact(
                        artifact_id=artifact_id,
                        tenant_id=tenant_id,
                    ) as verified:
                        adapter = AuditArchiveAdapter()
                        if directive.operation == "archive.preflight":
                            return adapter.preflight(verified)
                        if directive.operation == "archive.manifest":
                            return adapter.manifest(
                                verified,
                                offset=int(args.get("offset", 0)),
                                limit=int(args.get("limit", 100)),
                            )
                        if directive.operation == "archive.file_metadata":
                            return adapter.file_metadata(
                                verified,
                                member_name=str(args["member_name"]),
                            )
                        if directive.operation == "archive.read_text_member":
                            return adapter.read_text_member(
                                verified,
                                member_name=str(args["member_name"]),
                                offset=int(args.get("offset", 0)),
                                max_bytes=int(args.get("max_bytes", 16_000)),
                            )
                        if directive.operation == "archive.hash_member":
                            return adapter.hash_member(
                                verified,
                                member_name=str(args["member_name"]),
                            )
                raise AuditInvocationError("AUDIT_OPERATION_UNKNOWN")

            return archive_operation

        if directive.operation == "runtime.file_sha256":
            def runtime_hash():
                adapter = AuditRuntimeAdapter(
                    project_root=self._project_root,
                    module_allowlist=self._runtime_module_allowlist,
                )
                return adapter.file_sha256(str(args["module_id"]))

            return runtime_hash

        if directive.operation == "runtime.search_marker":
            def runtime_marker():
                adapter = AuditRuntimeAdapter(
                    project_root=self._project_root,
                    module_allowlist=self._runtime_module_allowlist,
                )
                return adapter.search_marker(
                    str(args["module_id"]),
                    marker=str(args["marker"]),
                    max_scan_bytes=int(args.get("max_scan_bytes", 1_000_000)),
                    max_matches=int(args.get("max_matches", 256)),
                )

            return runtime_marker

        raise AuditInvocationError("AUDIT_OPERATION_UNKNOWN", http_status=400)

    def invoke_if_directive(
        self,
        *,
        message: str,
        turn: CanonicalTurnContext,
        principal_roles,
    ) -> AuditInvocationOutcome | None:
        if not looks_like_audit_directive(message):
            return None

        if not self._directive_abuse_limiter.consume(
            tenant_id=turn.tenant_id,
            user_id=turn.user_id,
        ):
            raise AuditInvocationError(
                "AUDIT_DIRECTIVE_RATE_LIMITED",
                http_status=429,
            )

        try:
            directive = parse_audit_directive(message)
        except AuditDirectiveError as exc:
            self._trace(
                "directive_parse_failed",
                turn=turn,
                status="failed",
                error_code=exc.code,
            )
            raise AuditInvocationError(
                exc.code,
                http_status=_http_status_for(exc.code),
            ) from exc
        if directive is None:
            return None

        self._trace("directive_parsed", turn=turn, directive=directive, status="accepted")
        requested_canonical_agent_id = self._requested_canonical_agent_id(turn)
        preflight_reason = self._preflight_reason(
            turn=turn,
            requested_canonical_agent_id=requested_canonical_agent_id,
        )
        if preflight_reason is not None:
            self._trace(
                "policy_denied",
                turn=turn,
                directive=directive,
                status="denied",
                error_code=preflight_reason,
            )
            self._deny(
                turn=turn,
                requested_canonical_agent_id=requested_canonical_agent_id,
                directive=directive,
                reason=preflight_reason,
            )

        self._trace("policy_preflight_allowed", turn=turn, directive=directive, status="accepted")
        privileged_user = bool({"admin", "orkio_admin"}.intersection(set(principal_roles)))
        decision = self._authorize(
            directive=directive,
            turn=turn,
            requested_canonical_agent_id=requested_canonical_agent_id,
            privileged_user=privileged_user,
        )
        if not decision.allowed:
            self._trace(
                "policy_denied",
                turn=turn,
                directive=directive,
                status="denied",
                error_code=decision.reason,
            )
            self._deny(
                turn=turn,
                requested_canonical_agent_id=requested_canonical_agent_id,
                directive=directive,
                reason=decision.reason,
            )

        self._trace("policy_allowed", turn=turn, directive=directive, status="accepted")
        spec = self._registry.get(directive.spec.capability_id)
        self._trace("dispatcher_enter", turn=turn, directive=directive, status="running")
        request_binding = _build_request_binding(directive, turn=turn)
        operation = self._operation(directive, tenant_id=turn.tenant_id)
        try:
            self._trace("adapter_started", turn=turn, directive=directive, status="running")
            guarded = self._guard.execute(spec=spec, operation=operation)
            self._trace("adapter_completed", turn=turn, directive=directive, status="completed")
            raw_data = guarded.data
            if not isinstance(raw_data, dict):
                raise AuditInvocationError("AUDIT_OUTPUT_TYPE_FORBIDDEN")
            request_result_binding = _verify_request_result_binding(
                directive=directive,
                request_binding=request_binding,
                result=raw_data,
            )
            evidence_data = {
                "governance_mode": AUDIT_GOVERNANCE_MODE,
                "operation": directive.operation,
                "request_binding": request_binding,
                "request_result_binding": request_result_binding,
                "output_changed_by_sanitizer": guarded.sanitized,
                "serialized_bytes": guarded.serialized_bytes,
                "result": raw_data,
            }
        except Exception as exc:
            if isinstance(exc, AuditArchiveSourceError):
                internal_reason = str(exc)
                if internal_reason in {
                    "AUDIT_ARCHIVE_NOT_FOUND",
                    "AUDIT_ARCHIVE_ARTIFACT_TENANT_MISMATCH",
                }:
                    self._deny(
                        turn=turn,
                        requested_canonical_agent_id=requested_canonical_agent_id,
                        directive=directive,
                        reason=internal_reason,
                        public_reason="AUDIT_ARCHIVE_NOT_FOUND",
                    )

            code = _error_code(exc, "AUDIT_CAPABILITY_EXECUTION_FAILED")
            self._trace(
                "adapter_failed",
                turn=turn,
                directive=directive,
                status="failed",
                error_code=code,
            )
            try:
                envelope, append_result = self._persist_evidence(
                    turn=turn,
                    requested_canonical_agent_id=requested_canonical_agent_id,
                    directive=directive,
                    capability_decision="ALLOW",
                    capability_decision_reason="ALLOW",
                    status="failed",
                    sanitized=True,
                    read_executed=True,
                    data={
                        "governance_mode": AUDIT_GOVERNANCE_MODE,
                        "operation": directive.operation,
                        "request_binding": request_binding,
                    },
                    error_code=code,
                )
            except AuditInvocationError:
                raise
            ref = {
                "audit_execution_id": envelope["audit_execution_id"],
                "capability_id": envelope["capability_id"],
                "capability_version": envelope["capability_version"],
                "status": "failed",
                "evidence_sha256": append_result.evidence_sha256,
            }
            self._trace(
                "invocation_failed",
                turn=turn,
                directive=directive,
                audit_execution_id=envelope["audit_execution_id"],
                status="failed",
                error_code=code,
            )
            raise AuditInvocationError(
                code,
                http_status=_http_status_for(code),
                audit_reference=ref,
            ) from exc

        envelope, append_result = self._persist_evidence(
            turn=turn,
            requested_canonical_agent_id=requested_canonical_agent_id,
            directive=directive,
            capability_decision="ALLOW",
            capability_decision_reason="ALLOW",
            status="completed",
            sanitized=True,
            read_executed=True,
            data=evidence_data,
            error_code=None,
        )
        self._trace(
            "invocation_completed",
            turn=turn,
            directive=directive,
            audit_execution_id=envelope["audit_execution_id"],
            status="completed",
        )
        return AuditInvocationOutcome(
            operation=directive.operation,
            audit_execution_id=envelope["audit_execution_id"],
            capability_id=envelope["capability_id"],
            capability_version=envelope["capability_version"],
            status="completed",
            evidence_sha256=append_result.evidence_sha256,
            data=evidence_data,
        )
