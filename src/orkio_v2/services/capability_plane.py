from __future__ import annotations

from .capability_policy import CapabilityPolicy
from .external_read_tool import external_read_context_messages
from .python_tool import python_context_messages
from .python_runtime.contracts import PythonRuntimeContext


def privileged_roles(roles: frozenset[str] | set[str] | tuple[str, ...]) -> bool:
    return bool({"admin", "orkio_admin"}.intersection(set(roles)))


def capability_manifest_message(
    policy: CapabilityPolicy,
    *,
    privileged: bool,
) -> dict[str, str]:
    manifest = policy.manifest(privileged=privileged)
    py = manifest["python"]
    ext = manifest["external_read"]
    audit = manifest["audit"]
    return {
        "role": "system",
        "content": (
            "ORKIO EFFECTIVE CAPABILITIES FOR THIS TURN — authoritative runtime policy.\n"
            f"python_execute={str(bool(py['execute'])).lower()} "
            f"python_enabled={str(bool(py['enabled'])).lower()} "
            f"python_available_now={str(bool(py['availableNow'])).lower()} "
            f"python_runtime={py['runtime']} "
            f"python_runtime_proved={str(bool(py['runtimeProved'])).lower()} "
            f"python_premium_qualified={str(bool(py['premiumQualified'])).lower()} "
            f"python_external_qualification_approved={str(bool(py.get('external_qualification_approved', False))).lower()} "
            f"python_network_policy={py['network_policy']} "
            f"python_network_enforced={str(bool(py['network_enforced'])).lower()} "
            f"python_filesystem_isolated={str(bool(py['filesystem_isolated'])).lower()}\n"
            f"external_read={str(bool(ext['enabled'])).lower()} "
            f"allowed_domains={','.join(ext['allowed_domains']) or '[none]'}\n"
            f"audit_file_inspect={str(bool(audit['file_inspect'])).lower()} "
            f"audit_archive_inspect={str(bool(audit['archive_inspect'])).lower()} "
            f"audit_runtime_file_sha256={str(bool(audit['runtime_file_sha256'])).lower()} "
            f"audit_runtime_search_marker={str(bool(audit['runtime_search_marker'])).lower()} "
            "audit_network=false audit_write=false\n"
            "external_write=false proposal_only=true\n"
            "Generate source code as text when requested. "
            "Only claim Python execution or external-link reading when a trusted tool result "
            "message is present in this turn."
        ),
    }


async def runtime_capability_messages(
    *,
    message: str,
    roles,
    tenant_id: str | None = None,
    user_id: str | None = None,
    thread_id: str | None = None,
    agent_id: str | None = None,
    request_id: str | None = None,
    db=None,
) -> list[dict[str, str]]:
    policy = CapabilityPolicy.from_env()
    privileged = privileged_roles(roles)
    messages = [capability_manifest_message(policy, privileged=privileged)]
    runtime_context = (
        PythonRuntimeContext(
            tenant_id=tenant_id,
            user_id=user_id,
            thread_id=thread_id,
            agent_id=agent_id,
            request_id=request_id,
        )
        if tenant_id and user_id
        else None
    )
    messages.extend(
        await python_context_messages(
            policy,
            message=message,
            privileged=privileged,
            runtime_context=runtime_context,
            db=db,
        )
    )
    messages.extend(
        await external_read_context_messages(
            policy,
            message=message,
            privileged=privileged,
        )
    )
    return messages
