from __future__ import annotations

import os
import re
from urllib.parse import urlparse
from dataclasses import dataclass, field


class CapabilityPolicyError(RuntimeError):
    code = "CAPABILITY_POLICY_ERROR"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise CapabilityPolicyError(f"{name}_INVALID")


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise CapabilityPolicyError(f"{name}_INVALID") from exc
    if value < minimum or value > maximum:
        raise CapabilityPolicyError(f"{name}_OUT_OF_RANGE")
    return value


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise CapabilityPolicyError(f"{name}_INVALID") from exc
    if value < minimum or value > maximum:
        raise CapabilityPolicyError(f"{name}_OUT_OF_RANGE")
    return value



def _env_choice(name: str, default: str, allowed: set[str]) -> str:
    raw = os.getenv(name)
    value = (raw.strip().lower() if raw is not None else default)
    if value not in allowed:
        raise CapabilityPolicyError(f"{name}_INVALID")
    return value


def _normalize_railway_runtime_environment(raw: str) -> str:
    value = (raw or "").strip().lower()
    if not value:
        return "unknown"
    if value in {"development", "test", "staging", "production"}:
        return value

    # Railway environment names may be free-form. Normalize only unambiguous
    # exact tokens separated by non-alphanumeric delimiters. Typos and arbitrary
    # names must never become development implicitly.
    tokens = {
        token
        for token in re.split(r"[^a-z0-9]+", value)
        if token
    }
    matches: set[str] = set()
    aliases = {
        "development": {"development", "dev"},
        "test": {"test", "testing"},
        "staging": {"staging", "stage"},
        "production": {"production", "prod"},
    }
    for canonical, accepted in aliases.items():
        if tokens & accepted:
            matches.add(canonical)
    if len(matches) == 1:
        return next(iter(matches))
    return "unknown"


def _python_runtime_environment() -> str:
    platform_raw = os.getenv("PLATFORM_ENVIRONMENT")
    if platform_raw is not None:
        value = platform_raw.strip().lower()
        if value not in {"development", "test", "staging", "production"}:
            raise CapabilityPolicyError("PLATFORM_ENVIRONMENT_INVALID")
        return value

    railway_raw = os.getenv("RAILWAY_ENVIRONMENT_NAME")
    if railway_raw is None:
        return "unknown"
    return _normalize_railway_runtime_environment(railway_raw)


def _python_runtime_base_url(environment: str) -> str:
    raw = os.getenv("PLATFORM_PYTHON_SANDBOX_BASE_URL", "").strip().rstrip("/")
    if not raw:
        return ""
    parsed = urlparse(raw)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise CapabilityPolicyError("PLATFORM_PYTHON_SANDBOX_BASE_URL_INVALID")
    if parsed.scheme == "https" and parsed.netloc:
        return raw
    if (
        environment in {"development", "test"}
        and parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost"}
        and parsed.netloc
    ):
        return raw
    raise CapabilityPolicyError("PLATFORM_PYTHON_SANDBOX_BASE_URL_HTTPS_REQUIRED")


def _runtime_image_digest(name: str) -> str:
    value = os.getenv(name, "").strip().lower()
    if not value:
        return ""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise CapabilityPolicyError(f"{name}_INVALID")
    return value


def _runtime_signing_key(name: str) -> str:
    value = os.getenv(name, "")
    if not value:
        return ""
    if len(value.encode("utf-8")) < 32:
        raise CapabilityPolicyError(f"{name}_TOO_SHORT")
    return value


def _csv_tokens(name: str) -> tuple[str, ...]:
    values: list[str] = []
    seen: set[str] = set()
    for raw in os.getenv(name, "").split(","):
        item = raw.strip().lower()
        if not item:
            continue
        if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-_.:" for ch in item):
            raise CapabilityPolicyError(f"{name}_INVALID")
        if item not in seen:
            seen.add(item)
            values.append(item)
    return tuple(values)

def _domains() -> tuple[str, ...]:
    values: list[str] = []
    seen: set[str] = set()
    for raw in os.getenv("PLATFORM_EXTERNAL_READ_ALLOWED_DOMAINS", "").split(","):
        item = raw.strip().lower().strip(".")
        if not item:
            continue
        if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-." for ch in item):
            raise CapabilityPolicyError("PLATFORM_EXTERNAL_READ_ALLOWED_DOMAINS_INVALID")
        if ".." in item or item.startswith("-") or item.endswith("-"):
            raise CapabilityPolicyError("PLATFORM_EXTERNAL_READ_ALLOWED_DOMAINS_INVALID")
        if item not in seen:
            seen.add(item)
            values.append(item)
    return tuple(values)


@dataclass(frozen=True, slots=True)
class CapabilityPolicy:
    python_enabled: bool
    python_timeout_seconds: float
    python_max_code_bytes: int
    python_max_output_bytes: int
    external_read_enabled: bool
    external_read_allowed_domains: tuple[str, ...]
    external_read_timeout_seconds: float
    external_read_max_bytes: int
    external_read_max_urls_per_turn: int
    python_runtime_mode: str = "disabled"
    python_runtime_adapter: str = "unconfigured"
    python_legacy_local_test_enabled: bool = False
    python_runtime_environment: str = "development"
    python_runtime_profile_id: str = "python-analysis-lite-v1"
    python_runtime_qualified: bool = False
    python_runtime_base_url: str = ""
    python_runtime_api_token: str = field(default="", repr=False)
    python_runtime_signing_key: str = field(default="", repr=False)
    python_runtime_expected_provider: str = ""
    python_runtime_expected_image_digest: str = ""
    python_runtime_request_timeout_seconds: float = 10.0
    python_runtime_request_ttl_seconds: int = 30
    python_runtime_wall_clock_seconds: float = 5.0
    python_runtime_cpu_cores: float = 1.0
    python_runtime_memory_mb: int = 512
    python_runtime_max_processes: int = 16
    python_runtime_max_output_files: int = 8
    python_runtime_max_output_bytes: int = 10_000_000
    audit_evidence_capabilities_enabled: bool = False
    audit_file_inspect_enabled: bool = False
    audit_archive_inspect_enabled: bool = False
    audit_runtime_inspect_enabled: bool = False
    audit_runtime_file_sha256_enabled: bool = False
    audit_runtime_search_marker_enabled: bool = False
    audit_allowed_agent_ids: tuple[str, ...] = ()
    audit_allowed_tenant_ids: tuple[str, ...] = ()
    audit_allowed_environments: tuple[str, ...] = ()
    audit_timeout_seconds: float = 3.0
    audit_max_output_bytes: int = 128_000
    audit_governed_invocation_enabled: bool = False
    audit_rate_limit_window_seconds: int = 60
    audit_user_rate_limit_per_window: int = 4
    audit_tenant_rate_limit_per_window: int = 20
    audit_directive_user_rate_limit: int = 12

    @classmethod
    def from_env(cls) -> "CapabilityPolicy":
        runtime_environment = _python_runtime_environment()
        policy = cls(
            python_enabled=_env_bool("PLATFORM_PYTHON_TOOL_ENABLED", False),
            python_timeout_seconds=_env_float(
                "PLATFORM_PYTHON_TOOL_TIMEOUT_SECONDS", 3.0, 0.25, 10.0
            ),
            python_max_code_bytes=_env_int(
                "PLATFORM_PYTHON_TOOL_MAX_CODE_BYTES", 20_000, 256, 100_000
            ),
            python_max_output_bytes=_env_int(
                "PLATFORM_PYTHON_TOOL_MAX_OUTPUT_BYTES", 64_000, 1_024, 250_000
            ),
            external_read_enabled=_env_bool("PLATFORM_EXTERNAL_READ_ENABLED", False),
            external_read_allowed_domains=_domains(),
            external_read_timeout_seconds=_env_float(
                "PLATFORM_EXTERNAL_READ_TIMEOUT_SECONDS", 5.0, 0.5, 15.0
            ),
            external_read_max_bytes=_env_int(
                "PLATFORM_EXTERNAL_READ_MAX_BYTES", 500_000, 1_024, 2_000_000
            ),
            external_read_max_urls_per_turn=_env_int(
                "PLATFORM_EXTERNAL_READ_MAX_URLS_PER_TURN", 2, 1, 4
            ),
            python_runtime_mode=_env_choice(
                "PLATFORM_PYTHON_RUNTIME_MODE",
                "disabled",
                {"disabled", "legacy_local_test", "external"},
            ),
            python_runtime_adapter=_env_choice(
                "PLATFORM_PYTHON_RUNTIME_ADAPTER",
                "unconfigured",
                {"unconfigured", "remote_http"},
            ),
            python_legacy_local_test_enabled=_env_bool(
                "PLATFORM_PYTHON_LEGACY_LOCAL_TEST_ENABLED", False
            ),
            python_runtime_environment=runtime_environment,
            python_runtime_profile_id=(
                os.getenv("PLATFORM_PYTHON_RUNTIME_PROFILE_ID", "python-analysis-lite-v1").strip()
                or "python-analysis-lite-v1"
            ),
            python_runtime_qualified=_env_bool(
                "PLATFORM_PYTHON_RUNTIME_QUALIFIED", False
            ),
            python_runtime_base_url=_python_runtime_base_url(runtime_environment),
            python_runtime_api_token=os.getenv(
                "PLATFORM_PYTHON_SANDBOX_API_TOKEN", ""
            ).strip(),
            python_runtime_signing_key=_runtime_signing_key(
                "PLATFORM_PYTHON_SANDBOX_SIGNING_KEY"
            ),
            python_runtime_expected_provider=os.getenv(
                "PLATFORM_PYTHON_SANDBOX_EXPECTED_PROVIDER", ""
            ).strip().lower(),
            python_runtime_expected_image_digest=_runtime_image_digest(
                "PLATFORM_PYTHON_SANDBOX_EXPECTED_IMAGE_DIGEST"
            ),
            python_runtime_request_timeout_seconds=_env_float(
                "PLATFORM_PYTHON_SANDBOX_REQUEST_TIMEOUT_SECONDS", 10.0, 1.0, 60.0
            ),
            python_runtime_request_ttl_seconds=_env_int(
                "PLATFORM_PYTHON_SANDBOX_REQUEST_TTL_SECONDS", 30, 5, 120
            ),
            python_runtime_wall_clock_seconds=_env_float(
                "PLATFORM_PYTHON_SANDBOX_WALL_CLOCK_SECONDS", 5.0, 0.5, 60.0
            ),
            python_runtime_cpu_cores=_env_float(
                "PLATFORM_PYTHON_SANDBOX_CPU_CORES", 1.0, 0.1, 8.0
            ),
            python_runtime_memory_mb=_env_int(
                "PLATFORM_PYTHON_SANDBOX_MEMORY_MB", 512, 64, 8192
            ),
            python_runtime_max_processes=_env_int(
                "PLATFORM_PYTHON_SANDBOX_MAX_PROCESSES", 16, 1, 128
            ),
            python_runtime_max_output_files=_env_int(
                "PLATFORM_PYTHON_SANDBOX_MAX_OUTPUT_FILES", 8, 0, 32
            ),
            python_runtime_max_output_bytes=_env_int(
                "PLATFORM_PYTHON_SANDBOX_MAX_OUTPUT_BYTES",
                10_000_000,
                0,
                100_000_000,
            ),
            audit_evidence_capabilities_enabled=_env_bool(
                "PLATFORM_AUDIT_EVIDENCE_CAPABILITIES_ENABLED", False
            ),
            audit_file_inspect_enabled=_env_bool(
                "PLATFORM_AUDIT_FILE_INSPECT_ENABLED", False
            ),
            audit_archive_inspect_enabled=_env_bool(
                "PLATFORM_AUDIT_ARCHIVE_INSPECT_ENABLED", False
            ),
            audit_runtime_inspect_enabled=_env_bool(
                "PLATFORM_AUDIT_RUNTIME_INSPECT_ENABLED", False
            ),
            audit_runtime_file_sha256_enabled=_env_bool(
                "PLATFORM_AUDIT_RUNTIME_FILE_SHA256_ENABLED", False
            ),
            audit_runtime_search_marker_enabled=_env_bool(
                "PLATFORM_AUDIT_RUNTIME_SEARCH_MARKER_ENABLED", False
            ),
            audit_allowed_agent_ids=_csv_tokens("PLATFORM_AUDIT_ALLOWED_AGENT_IDS"),
            audit_allowed_tenant_ids=_csv_tokens("PLATFORM_AUDIT_ALLOWED_TENANT_IDS"),
            audit_allowed_environments=_csv_tokens("PLATFORM_AUDIT_ALLOWED_ENVIRONMENTS"),
            audit_timeout_seconds=_env_float(
                "PLATFORM_AUDIT_TIMEOUT_SECONDS", 3.0, 0.25, 15.0
            ),
            audit_max_output_bytes=_env_int(
                "PLATFORM_AUDIT_MAX_OUTPUT_BYTES", 128_000, 1_024, 1_000_000
            ),
            audit_governed_invocation_enabled=_env_bool(
                "PLATFORM_AUDIT_GOVERNED_INVOCATION_ENABLED", False
            ),
            audit_rate_limit_window_seconds=_env_int(
                "PLATFORM_AUDIT_RATE_LIMIT_WINDOW_SECONDS", 60, 60, 60
            ),
            audit_user_rate_limit_per_window=_env_int(
                "PLATFORM_AUDIT_USER_RATE_LIMIT_PER_WINDOW", 4, 1, 100
            ),
            audit_tenant_rate_limit_per_window=_env_int(
                "PLATFORM_AUDIT_TENANT_RATE_LIMIT_PER_WINDOW", 20, 1, 1000
            ),
            audit_directive_user_rate_limit=_env_int(
                "PLATFORM_AUDIT_DIRECTIVE_USER_RATE_LIMIT", 12, 1, 100
            ),
        )
        if policy.external_read_enabled and not policy.external_read_allowed_domains:
            raise CapabilityPolicyError("EXTERNAL_READ_ALLOWED_DOMAINS_REQUIRED")
        if policy.audit_tenant_rate_limit_per_window < policy.audit_user_rate_limit_per_window:
            raise CapabilityPolicyError("PLATFORM_AUDIT_RATE_LIMIT_INVALID")
        if policy.python_runtime_mode == "external" and policy.python_runtime_adapter == "remote_http":
            if not policy.python_runtime_base_url:
                raise CapabilityPolicyError("PYTHON_SANDBOX_BASE_URL_REQUIRED")
            if not policy.python_runtime_api_token:
                raise CapabilityPolicyError("PYTHON_SANDBOX_API_TOKEN_REQUIRED")
            if not policy.python_runtime_signing_key:
                raise CapabilityPolicyError("PYTHON_SANDBOX_SIGNING_KEY_REQUIRED")
            if not policy.python_runtime_expected_provider:
                raise CapabilityPolicyError("PYTHON_SANDBOX_EXPECTED_PROVIDER_REQUIRED")
            if not policy.python_runtime_expected_image_digest:
                raise CapabilityPolicyError("PYTHON_SANDBOX_EXPECTED_IMAGE_DIGEST_REQUIRED")
        return policy

    def python_runtime_state(self, *, privileged: bool) -> dict[str, object]:
        legacy_environment = self.python_runtime_environment in {"development", "test"}
        legacy_available = bool(
            self.python_enabled
            and privileged
            and self.python_runtime_mode == "legacy_local_test"
            and self.python_legacy_local_test_enabled
            and legacy_environment
        )
        external_requested = bool(
            self.python_enabled
            and privileged
            and self.python_runtime_mode == "external"
        )
        external_configured = bool(
            external_requested
            and self.python_runtime_adapter == "remote_http"
            and self.python_runtime_base_url
            and self.python_runtime_api_token
            and self.python_runtime_signing_key
            and self.python_runtime_expected_provider
            and self.python_runtime_expected_image_digest
        )
        external_available = bool(
            external_configured and self.python_runtime_qualified
        )
        available_now = bool(legacy_available or external_available)
        if self.python_runtime_mode == "legacy_local_test":
            runtime = "legacy_same_host_subprocess"
            network_policy = "NOT_OS_ENFORCED"
            filesystem_policy = "TEMP_CWD_NOT_SECURITY_BOUNDARY"
            network_enforced = False
            filesystem_isolated = False
        elif self.python_runtime_mode == "external":
            runtime = "external_isolated_sandbox"
            network_policy = "DENY_REQUIRED"
            filesystem_policy = "EPHEMERAL_ISOLATED_REQUIRED"
            # Configuration/approval means the call may be attempted; it is not
            # evidence that a real sandbox enforced these controls.
            network_enforced = False
            filesystem_isolated = False
        else:
            runtime = "disabled"
            network_policy = "DENY_REQUIRED"
            filesystem_policy = "EPHEMERAL_ISOLATED_REQUIRED"
            network_enforced = False
            filesystem_isolated = False
        return {
            "supported": True,
            "enabled": bool(self.python_enabled and privileged),
            "execute": available_now,
            "availableNow": available_now,
            # Configuration/approval never substitutes for runtime evidence.
            "runtimeProved": False,
            "premiumQualified": False,
            "runtime": runtime,
            "runtime_mode": self.python_runtime_mode,
            "runtime_adapter": self.python_runtime_adapter,
            "runtime_profile_id": self.python_runtime_profile_id,
            "legacy_local_test": legacy_available,
            "legacy_local_test_requested": bool(
                self.python_runtime_mode == "legacy_local_test"
                and self.python_legacy_local_test_enabled
            ),
            "external_configured": external_configured,
            "external_qualification_approved": bool(
                external_configured and self.python_runtime_qualified
            ),
            "runtime_artifact_bound": bool(
                external_configured and self.python_runtime_expected_image_digest
            ),
            "broker_request_signing": bool(
                external_configured and self.python_runtime_signing_key
            ),
            "broker_request_ttl_seconds": self.python_runtime_request_ttl_seconds,
            "broker_response_request_binding_required": self.python_runtime_mode == "external",
            "environment": self.python_runtime_environment,
            "network_policy": network_policy,
            "network_enforcement_required": self.python_runtime_mode == "external",
            "network_enforced": network_enforced,
            "filesystem_policy": filesystem_policy,
            "filesystem_isolation_required": self.python_runtime_mode == "external",
            "filesystem_isolated": filesystem_isolated,
            "hard_cpu_limit_required": True,
            "hard_memory_limit_required": True,
            "process_limit_required": True,
            "resource_limits": {
                "wall_clock_seconds": self.python_runtime_wall_clock_seconds,
                "cpu_cores": self.python_runtime_cpu_cores,
                "memory_mb": self.python_runtime_memory_mb,
                "max_processes": self.python_runtime_max_processes,
                "max_output_files": self.python_runtime_max_output_files,
                "max_output_bytes": self.python_runtime_max_output_bytes,
            },
            "privileged_only": True,
        }

    def manifest(self, *, privileged: bool) -> dict[str, object]:
        return {
            "python": self.python_runtime_state(privileged=privileged),
            "external_read": {
                "enabled": bool(self.external_read_enabled and privileged),
                "https_only": True,
                "read_only": True,
                "allowed_domains": list(self.external_read_allowed_domains),
                "privileged_only": True,
            },
            "audit": {
                "governed_invocation": bool(
                    self.audit_governed_invocation_enabled and privileged
                ),
                "evidence_capabilities_enabled": bool(
                    self.audit_evidence_capabilities_enabled and privileged
                ),
                "file_inspect": bool(
                    self.audit_evidence_capabilities_enabled
                    and self.audit_file_inspect_enabled
                    and privileged
                ),
                "archive_inspect": bool(
                    self.audit_evidence_capabilities_enabled
                    and self.audit_archive_inspect_enabled
                    and privileged
                ),
                "runtime_file_sha256": bool(
                    self.audit_evidence_capabilities_enabled
                    and self.audit_runtime_inspect_enabled
                    and self.audit_runtime_file_sha256_enabled
                    and privileged
                ),
                "runtime_search_marker": bool(
                    self.audit_evidence_capabilities_enabled
                    and self.audit_runtime_inspect_enabled
                    and self.audit_runtime_search_marker_enabled
                    and privileged
                ),
                "network": False,
                "write": False,
                "allowed_agent_ids": list(self.audit_allowed_agent_ids),
                "allowed_tenant_ids": list(self.audit_allowed_tenant_ids),
                "allowed_environments": list(self.audit_allowed_environments),
                "rate_limit_window_seconds": self.audit_rate_limit_window_seconds,
                "user_rate_limit_per_window": self.audit_user_rate_limit_per_window,
                "tenant_rate_limit_per_window": self.audit_tenant_rate_limit_per_window,
                "directive_user_rate_limit": self.audit_directive_user_rate_limit,
            },
            "external_write": False,
            "proposal_only": True,
        }
