from __future__ import annotations

import logging
from sqlalchemy.orm import Session, sessionmaker

from ...models import AuditEvent
from .contracts import PythonExecutionRequest, PythonRuntimeResult


logger = logging.getLogger("orkio.python_runtime.audit")


def record_python_runtime_audit(
    db: Session | None,
    *,
    request: PythonExecutionRequest,
    status: str,
    result: PythonRuntimeResult | None = None,
    error_code: str | None = None,
) -> str | None:
    if db is None:
        return None

    metadata = {
        "execution_id": request.execution_id,
        "request_id": request.context.request_id,
        "thread_id": request.context.thread_id,
        "agent_id": request.context.agent_id,
        "code_sha256": request.code_sha256,
        "runtime_profile_id": request.runtime_profile_id,
        "runtime_profile_digest": request.runtime_profile_digest,
        "expected_runtime_image_digest": request.expected_runtime_image_digest,
        "network_policy": request.network_policy,
        "status": status,
        "error_code": error_code,
    }
    if result is not None:
        transport_binding = result.attestation.get("transport_binding")
        metadata.update(
            {
                "sandbox_execution_id": result.sandbox_execution_id,
                "sandbox_provider": result.sandbox_provider,
                "runtime_profile_digest": result.runtime_profile_digest,
                "duration_ms": result.duration_ms,
                "exit_code": result.exit_code,
                "truncated": result.truncated,
                "network_policy_enforced": result.network_policy_enforced,
                "filesystem_isolation_enforced": result.filesystem_isolation_enforced,
                "cpu_limit_enforced": result.cpu_limit_enforced,
                "memory_limit_enforced": result.memory_limit_enforced,
                "process_limit_enforced": result.process_limit_enforced,
                "ephemeral_filesystem_enforced": result.ephemeral_filesystem_enforced,
                "no_operational_secrets": result.no_operational_secrets,
                "runtime_image_digest": result.attestation.get("runtime_image_digest"),
                "broker_integrity_contract": (
                    transport_binding.get("integrity_contract")
                    if isinstance(transport_binding, dict)
                    else None
                ),
                "broker_request_nonce_sha256": (
                    transport_binding.get("request_nonce_sha256")
                    if isinstance(transport_binding, dict)
                    else None
                ),
                "broker_request_body_sha256": (
                    transport_binding.get("request_body_sha256")
                    if isinstance(transport_binding, dict)
                    else None
                ),
                "broker_request_expires_at": (
                    transport_binding.get("request_expires_at")
                    if isinstance(transport_binding, dict)
                    else None
                ),
                "broker_response_signature_verified": (
                    transport_binding.get("response_signature_verified")
                    if isinstance(transport_binding, dict)
                    else None
                ),
                "broker_response_request_binding_verified": (
                    transport_binding.get("response_request_binding_verified")
                    if isinstance(transport_binding, dict)
                    else None
                ),
                "output_count": len(result.outputs),
            }
        )

    event = AuditEvent(
        tenant_id=request.context.tenant_id,
        actor_id=request.context.user_id,
        action=f"PYTHON_RUNTIME_{status}",
        resource_type="python_execution",
        resource_id=request.execution_id,
        outcome="SUCCESS" if status in {"STARTED", "SUCCEEDED"} else status,
        metadata_json=metadata,
    )

    # Independent short transaction avoids committing unrelated chat/thread work.
    try:
        AuditSession = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
        with AuditSession() as audit_db:
            audit_db.add(event)
            audit_db.commit()
        return event.id
    except Exception:
        logger.exception(
            "PYTHON_RUNTIME_AUDIT_WRITE_FAILED execution_id=%s status=%s",
            request.execution_id,
            status,
        )
        return None
