from functools import lru_cache
import ipaddress
from typing import Literal
from pydantic import AliasChoices, Field, PrivateAttr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .provenance import resolve_build_provenance


_DEVELOPMENT_INVITATION_SECRET = "-".join(("development", "only", "change", "me", "32chars"))

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    environment: Literal["development","test","staging","production"] = Field(
        "development",
        validation_alias=AliasChoices("PLATFORM_ENVIRONMENT", "RAILWAY_ENVIRONMENT_NAME"),
    )
    platform_release_sha: str | None = Field(None, alias="PLATFORM_RELEASE_SHA")
    railway_git_commit_sha: str | None = Field(None, alias="RAILWAY_GIT_COMMIT_SHA")
    railway_deployment_id: str | None = Field(None, alias="RAILWAY_DEPLOYMENT_ID")
    railway_service_name: str | None = Field(None, alias="RAILWAY_SERVICE_NAME")
    release_sha: str = "unknown"
    _release_sha_source: str = PrivateAttr(default="unresolved")

    @property
    def release_sha_source(self) -> str:
        return self._release_sha_source
    database_url: str = Field("sqlite+pysqlite:///./orkio_v2.db", alias="DATABASE_URL")
    allowed_origins: str = Field("http://localhost:5173", alias="PLATFORM_ALLOWED_ORIGINS")

    auth_mode: Literal[
        "test",
        "external_required",
        "oidc_introspection",
        "native_session",
        "native_or_oidc",
    ] = Field("external_required", alias="PLATFORM_AUTH_MODE")
    demo_headers_enabled: bool = Field(False, alias="PLATFORM_DEMO_IDENTITY_HEADERS_ENABLED")
    platform_owner_subject: str | None = Field(None, alias="PLATFORM_OWNER_SUBJECT")
    native_auth_pepper: str = Field("", alias="PLATFORM_NATIVE_AUTH_PEPPER")
    native_session_secret: str = Field("", alias="PLATFORM_NATIVE_SESSION_SECRET")
    native_bootstrap_secret: str = Field("", alias="PLATFORM_NATIVE_BOOTSTRAP_SECRET")
    native_session_cookie_name: str = Field(
        "__Host-patroai_session", alias="PLATFORM_NATIVE_SESSION_COOKIE_NAME"
    )
    native_session_cookie_secure: bool = Field(
        False, alias="PLATFORM_NATIVE_SESSION_COOKIE_SECURE"
    )
    native_session_cookie_samesite: Literal["strict", "lax", "none"] = Field(
        "lax", alias="PLATFORM_NATIVE_SESSION_COOKIE_SAMESITE"
    )
    native_session_ttl_hours: int = Field(12, alias="PLATFORM_NATIVE_SESSION_TTL_HOURS")
    native_password_min_length: int = Field(12, alias="PLATFORM_NATIVE_PASSWORD_MIN_LENGTH")
    native_password_reset_ttl_minutes: int = Field(
        30, alias="PLATFORM_NATIVE_PASSWORD_RESET_TTL_MINUTES"
    )
    native_password_reset_base_url: str = Field(
        "", alias="PLATFORM_NATIVE_PASSWORD_RESET_BASE_URL"
    )
    resend_api_key: str = Field(
        "", validation_alias=AliasChoices("RESEND_API_KEY", "PLATFORM_RESEND_API_KEY")
    )
    resend_from: str = Field(
        "PatroAI <no-reply@patroai.com>",
        validation_alias=AliasChoices("RESEND_FROM", "PLATFORM_RESEND_FROM"),
    )
    resend_user_agent: str = Field("patroai-orkio/1.0", alias="PLATFORM_RESEND_USER_AGENT")
    native_login_max_failures: int = Field(8, alias="PLATFORM_NATIVE_LOGIN_MAX_FAILURES")
    native_login_lock_minutes: int = Field(15, alias="PLATFORM_NATIVE_LOGIN_LOCK_MINUTES")
    oidc_issuer: str | None = Field(None, alias="PLATFORM_OIDC_ISSUER")
    oidc_audience: str | None = Field(None, alias="PLATFORM_OIDC_AUDIENCE")
    oidc_introspection_endpoint: str | None = Field(None, alias="PLATFORM_OIDC_INTROSPECTION_ENDPOINT")
    oidc_introspection_client_id: str | None = Field(None, alias="PLATFORM_OIDC_INTROSPECTION_CLIENT_ID")
    oidc_introspection_client_secret: str | None = Field(None, alias="PLATFORM_OIDC_INTROSPECTION_CLIENT_SECRET")
    oidc_user_claim: str = Field("sub", alias="PLATFORM_OIDC_USER_CLAIM")
    oidc_tenant_claim: str = Field(
        "urn:zitadel:iam:user:resourceowner:id", alias="PLATFORM_OIDC_TENANT_CLAIM"
    )
    oidc_roles_claim: str = Field(
        "urn:zitadel:iam:org:project:roles", alias="PLATFORM_OIDC_ROLES_CLAIM"
    )
    oidc_http_timeout_seconds: float = Field(5, alias="PLATFORM_OIDC_HTTP_TIMEOUT_SECONDS")

    llm_primary_provider: Literal["openai","anthropic","google"] = Field(
        "openai", alias="PLATFORM_LLM_PRIMARY_PROVIDER"
    )
    llm_http_timeout_seconds: float = Field(30, alias="PLATFORM_LLM_HTTP_TIMEOUT_SECONDS")
    llm_provider_failover_enabled: bool = Field(
        False, alias="PLATFORM_LLM_PROVIDER_FAILOVER_ENABLED"
    )
    llm_auto_route_enabled: bool = Field(False, alias="PLATFORM_LLM_AUTO_ROUTE_ENABLED")
    internal_agent_consultation_enabled: bool = Field(
        False, alias="PLATFORM_INTERNAL_AGENT_CONSULTATION_ENABLED"
    )
    internal_agent_consultation_max: int = Field(
        2, alias="PLATFORM_INTERNAL_AGENT_CONSULTATION_MAX"
    )

    openai_api_key: str | None = Field(None, alias="OPENAI_API_KEY")
    openai_model: str = Field("gpt-5", alias="OPENAI_DEFAULT_MODEL")
    openai_api_base: str | None = Field(None, alias="OPENAI_API_BASE")

    anthropic_api_key: str | None = Field(None, alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field("claude-sonnet-5", alias="ANTHROPIC_DEFAULT_MODEL")
    anthropic_api_base: str = Field(
        "https://api.anthropic.com/v1", alias="ANTHROPIC_API_BASE"
    )
    anthropic_max_tokens: int = Field(4096, alias="ANTHROPIC_MAX_TOKENS")

    google_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    )
    google_model: str = Field("gemini-3.6-flash", alias="GOOGLE_DEFAULT_MODEL")
    google_api_base: str = Field(
        "https://generativelanguage.googleapis.com/v1beta", alias="GOOGLE_API_BASE"
    )
    google_max_output_tokens: int = Field(4096, alias="GOOGLE_MAX_OUTPUT_TOKENS")

    founder_council_enabled: bool = Field(False, alias="PLATFORM_FOUNDER_COUNCIL_ENABLED")
    founder_council_min_configured_providers: int = Field(
        2, alias="PLATFORM_FOUNDER_COUNCIL_MIN_CONFIGURED_PROVIDERS"
    )
    realtime_streaming_enabled: bool = Field(True, alias="PLATFORM_REALTIME_STREAMING_ENABLED")

    invitation_secret: str = Field(_DEVELOPMENT_INVITATION_SECRET, alias="PLATFORM_INVITATION_TOKEN_SECRET")
    invitation_ttl_hours: int = Field(72, alias="PLATFORM_INVITATION_TTL_HOURS")
    invitation_base_url: str = Field("http://localhost:5173/invite", alias="PLATFORM_INVITATION_BASE_URL")

    # Premium platform onboarding. It is independent from thread invitations and
    # remains fail-closed until explicitly enabled and configured.
    platform_invitation_enabled: bool = Field(
        False, alias="PLATFORM_USER_INVITATION_ENABLED"
    )
    platform_invitation_secret: str = Field(
        "", alias="PLATFORM_USER_INVITATION_SECRET"
    )
    platform_invitation_ttl_hours: int = Field(
        72, alias="PLATFORM_USER_INVITATION_TTL_HOURS"
    )
    platform_invitation_base_url: str = Field(
        "http://localhost:5173/activate", alias="PLATFORM_USER_INVITATION_BASE_URL"
    )
    platform_invitation_allowed_roles: str = Field(
        "member", alias="PLATFORM_USER_INVITATION_ALLOWED_ROLES"
    )

    platform_activation_trusted_proxy_cidrs: str = Field(
        "", alias="PLATFORM_ACTIVATION_TRUSTED_PROXY_CIDRS"
    )
    platform_activation_rate_limit_backend: Literal["memory", "external"] = Field(
        "memory", alias="PLATFORM_ACTIVATION_RATE_LIMIT_BACKEND"
    )
    platform_activation_rate_limit_window_seconds: int = Field(
        60, alias="PLATFORM_ACTIVATION_RATE_LIMIT_WINDOW_SECONDS"
    )
    platform_activation_status_rate_limit_per_window: int = Field(
        20, alias="PLATFORM_ACTIVATION_STATUS_RATE_LIMIT_PER_WINDOW"
    )
    platform_activation_accept_rate_limit_per_window: int = Field(
        8, alias="PLATFORM_ACTIVATION_ACCEPT_RATE_LIMIT_PER_WINDOW"
    )
    platform_activation_max_body_bytes: int = Field(
        16 * 1024, alias="PLATFORM_ACTIVATION_MAX_BODY_BYTES"
    )

    access_gate_enabled: bool = Field(False, alias="PLATFORM_ACCESS_GATE_ENABLED")
    access_gate_code_hashes: str = Field("", alias="PLATFORM_ACCESS_GATE_CODE_HASHES")
    access_gate_signing_secret: str = Field("", alias="PLATFORM_ACCESS_GATE_SIGNING_SECRET")
    access_gate_tenant_id: str = Field("", alias="PLATFORM_ACCESS_GATE_TENANT_ID")
    access_gate_ttl_seconds: int = Field(600, alias="PLATFORM_ACCESS_GATE_TTL_SECONDS")
    admin_email_allowlist: str = Field(
        "daniel@patroai.com,patroaiconsultech@gmail.com",
        alias="PLATFORM_ADMIN_EMAIL_ALLOWLIST",
    )

    artifacts_enabled: bool = Field(False, alias="PLATFORM_ARTIFACTS_ENABLED")
    artifact_storage_backend: Literal["local", "s3"] = Field("local", alias="PLATFORM_ARTIFACT_STORAGE_BACKEND")
    artifact_storage_path: str = Field("./data/artifacts", alias="PLATFORM_ARTIFACT_STORAGE_PATH")
    artifact_storage_bucket: str = Field("", alias="PLATFORM_ARTIFACT_STORAGE_BUCKET")
    artifact_storage_region: str = Field("us-east-1", alias="PLATFORM_ARTIFACT_STORAGE_REGION")
    artifact_storage_endpoint_url: str | None = Field(None, alias="PLATFORM_ARTIFACT_STORAGE_ENDPOINT_URL")
    artifact_storage_access_key_id: str = Field("", alias="PLATFORM_ARTIFACT_STORAGE_ACCESS_KEY_ID")
    artifact_storage_secret_access_key: str = Field("", alias="PLATFORM_ARTIFACT_STORAGE_SECRET_ACCESS_KEY")
    artifact_storage_sse: Literal["AES256", "aws:kms"] = Field("AES256", alias="PLATFORM_ARTIFACT_STORAGE_SSE")
    artifact_storage_kms_key_id: str = Field("", alias="PLATFORM_ARTIFACT_STORAGE_KMS_KEY_ID")
    artifact_storage_prefix: str = Field("efata", alias="PLATFORM_ARTIFACT_STORAGE_PREFIX")
    artifact_storage_path: str = Field("./data/artifacts", alias="PLATFORM_ARTIFACT_STORAGE_PATH")
    max_upload_bytes: int = Field(10_000_000, alias="PLATFORM_MAX_UPLOAD_BYTES")


    billing_enabled: bool = Field(False, alias="PLATFORM_BILLING_ENABLED")
    billing_live_mode_enabled: bool = Field(False, alias="PLATFORM_BILLING_LIVE_MODE_ENABLED")
    billing_provider: Literal["disabled", "asaas"] = Field(
        "disabled", alias="PLATFORM_BILLING_PROVIDER"
    )
    billing_plan_catalog_json: str = Field("{}", alias="PLATFORM_BILLING_PLAN_CATALOG_JSON")
    billing_topup_catalog_json: str = Field("{}", alias="PLATFORM_BILLING_TOPUP_CATALOG_JSON")
    billing_usd_brl: float = Field(5.0, alias="PLATFORM_BILLING_USD_BRL")
    billing_checkout_success_url: str = Field(
        "", alias="PLATFORM_BILLING_CHECKOUT_SUCCESS_URL"
    )
    billing_http_timeout_seconds: float = Field(
        10.0, alias="PLATFORM_BILLING_HTTP_TIMEOUT_SECONDS"
    )
    asaas_api_key: str = Field("", alias="ASAAS_API_KEY")
    asaas_webhook_token: str = Field("", alias="ASAAS_WEBHOOK_TOKEN")
    asaas_api_base_url: str = Field(
        "https://api-sandbox.asaas.com/v3", alias="ASAAS_API_BASE_URL"
    )

    knowledge_plane_enabled: bool = Field(True, alias="PLATFORM_KNOWLEDGE_PLANE_ENABLED")
    knowledge_context_max_files: int = Field(8, alias="PLATFORM_KNOWLEDGE_CONTEXT_MAX_FILES")
    knowledge_context_max_chars: int = Field(60_000, alias="PLATFORM_KNOWLEDGE_CONTEXT_MAX_CHARS")
    knowledge_context_max_chars_per_file: int = Field(
        16_000, alias="PLATFORM_KNOWLEDGE_CONTEXT_MAX_CHARS_PER_FILE"
    )
    large_document_pipeline_enabled: bool = Field(
        False, alias="PLATFORM_LARGE_DOCUMENT_PIPELINE_ENABLED"
    )
    knowledge_large_document_max_upload_bytes: int = Field(
        524_288_000, alias="PLATFORM_KNOWLEDGE_MAX_UPLOAD_BYTES"
    )
    knowledge_large_document_auto_process_bytes: int = Field(
        32_000_000, alias="PLATFORM_KNOWLEDGE_AUTO_PROCESS_BYTES"
    )
    knowledge_large_document_max_pdf_pages: int = Field(
        5_000, alias="PLATFORM_KNOWLEDGE_MAX_PDF_PAGES"
    )
    knowledge_chunk_target_chars: int = Field(
        6_000, alias="PLATFORM_KNOWLEDGE_CHUNK_TARGET_CHARS"
    )
    knowledge_chunk_overlap_chars: int = Field(
        500, alias="PLATFORM_KNOWLEDGE_CHUNK_OVERLAP_CHARS"
    )
    knowledge_retrieval_top_k: int = Field(
        12, alias="PLATFORM_KNOWLEDGE_RETRIEVAL_TOP_K"
    )
    knowledge_selective_context_enabled: bool = Field(
        False, alias="PLATFORM_KNOWLEDGE_SELECTIVE_CONTEXT_ENABLED"
    )

    unified_document_intake_enabled: bool = Field(
        False, alias="PLATFORM_UNIFIED_DOCUMENT_INTAKE_ENABLED"
    )
    document_intake_large_paste_threshold_chars: int = Field(
        100_000, alias="PLATFORM_DOCUMENT_INTAKE_LARGE_PASTE_THRESHOLD_CHARS"
    )
    document_intake_large_paste_max_chars: int = Field(
        5_000_000, alias="PLATFORM_DOCUMENT_INTAKE_LARGE_PASTE_MAX_CHARS"
    )
    document_intake_large_paste_max_bytes: int = Field(
        20_000_000, alias="PLATFORM_DOCUMENT_INTAKE_LARGE_PASTE_MAX_BYTES"
    )
    document_intake_manifest_max_bytes: int = Field(
        2_000_000, alias="PLATFORM_DOCUMENT_INTAKE_MANIFEST_MAX_BYTES"
    )

    document_context_enabled: bool = Field(True, alias="PLATFORM_DOCUMENT_CONTEXT_ENABLED")
    document_context_max_files: int = Field(6, alias="PLATFORM_DOCUMENT_CONTEXT_MAX_FILES")
    document_context_max_chars: int = Field(48_000, alias="PLATFORM_DOCUMENT_CONTEXT_MAX_CHARS")
    document_context_max_chars_per_file: int = Field(20_000, alias="PLATFORM_DOCUMENT_CONTEXT_MAX_CHARS_PER_FILE")
    document_context_max_pdf_pages: int = Field(40, alias="PLATFORM_DOCUMENT_CONTEXT_MAX_PDF_PAGES")
    document_ingestion_max_archive_entries: int = Field(512, alias="PLATFORM_DOCUMENT_INGESTION_MAX_ARCHIVE_ENTRIES")
    document_ingestion_max_total_uncompressed_bytes: int = Field(64_000_000, alias="PLATFORM_DOCUMENT_INGESTION_MAX_TOTAL_UNCOMPRESSED_BYTES")
    document_ingestion_max_member_bytes: int = Field(16_000_000, alias="PLATFORM_DOCUMENT_INGESTION_MAX_MEMBER_BYTES")
    document_ingestion_docx_max_xml_bytes: int = Field(2_000_000, alias="PLATFORM_DOCUMENT_INGESTION_DOCX_MAX_XML_BYTES")

    github_enabled: bool = Field(False, alias="PLATFORM_GITHUB_INTEGRATION_ENABLED")
    github_read_only: bool = Field(True, alias="PLATFORM_GITHUB_READ_ONLY")
    github_allowed_repositories: str = Field("", alias="PLATFORM_GITHUB_ALLOWED_REPOSITORIES")
    github_api_base: str = Field("https://api.github.com", alias="PLATFORM_GITHUB_API_BASE")
    github_read_token: str = Field("", alias="PLATFORM_GITHUB_READ_TOKEN")
    github_http_timeout_seconds: float = Field(5.0, alias="PLATFORM_GITHUB_HTTP_TIMEOUT_SECONDS")
    github_max_file_bytes: int = Field(250000, alias="PLATFORM_GITHUB_MAX_FILE_BYTES")
    github_max_tree_entries: int = Field(5000, alias="PLATFORM_GITHUB_MAX_TREE_ENTRIES")
    github_snapshot_max_files: int = Field(8, alias="PLATFORM_GITHUB_SNAPSHOT_MAX_FILES")
    github_snapshot_max_chars: int = Field(60000, alias="PLATFORM_GITHUB_SNAPSHOT_MAX_CHARS")

    voice_enabled: bool = Field(False, alias="PLATFORM_REALTIME_VOICE_ENABLED")
    voice_provider: str = Field("disabled", alias="PLATFORM_VOICE_PROVIDER")
    voice_bindings_json: str = Field("{}", alias="PLATFORM_VOICE_BINDINGS_JSON")

    tts_enabled: bool = Field(False, alias="PLATFORM_TTS_ENABLED")
    tts_provider: Literal["disabled","openai"] = Field("disabled", alias="PLATFORM_TTS_PROVIDER")
    tts_http_timeout_seconds: float = Field(20.0, alias="PLATFORM_TTS_HTTP_TIMEOUT_SECONDS")
    tts_max_chars: int = Field(4096, alias="PLATFORM_TTS_MAX_CHARS")
    tts_user_rate_limit_per_minute: int = Field(12, alias="PLATFORM_TTS_USER_RATE_LIMIT_PER_MINUTE")
    tts_tenant_rate_limit_per_minute: int = Field(60, alias="PLATFORM_TTS_TENANT_RATE_LIMIT_PER_MINUTE")
    tts_message_rate_limit_per_minute: int = Field(4, alias="PLATFORM_TTS_MESSAGE_RATE_LIMIT_PER_MINUTE")
    tts_cache_enabled: bool = Field(True, alias="PLATFORM_TTS_CACHE_ENABLED")
    tts_cache_path: str = Field("./data/tts-cache", alias="PLATFORM_TTS_CACHE_PATH")

    realtime_bridge_enabled: bool = Field(False, alias="PLATFORM_REALTIME_BRIDGE_ENABLED")
    realtime_transcription_model: str = Field(
        "gpt-4o-mini-transcribe", alias="PLATFORM_REALTIME_TRANSCRIPTION_MODEL"
    )

    stt_enabled: bool = Field(False, alias="PLATFORM_STT_ENABLED")
    stt_provider: Literal["disabled","faster_whisper"] = Field(
        "disabled", alias="PLATFORM_STT_PROVIDER"
    )
    stt_model: str = Field("small", alias="PLATFORM_STT_MODEL")
    stt_device: Literal["cpu","cuda","auto"] = Field("cpu", alias="PLATFORM_STT_DEVICE")
    stt_compute_type: str = Field("int8", alias="PLATFORM_STT_COMPUTE_TYPE")
    stt_max_upload_bytes: int = Field(8_000_000, alias="PLATFORM_STT_MAX_UPLOAD_BYTES")
    stt_allowed_languages: str = Field("pt,en,es", alias="PLATFORM_STT_ALLOWED_LANGUAGES")
    stt_model_cache_dir: str = Field(
        "/opt/orkio/models/faster-whisper",
        alias="PLATFORM_STT_MODEL_CACHE_DIR",
    )
    stt_local_files_only: bool = Field(False, alias="PLATFORM_STT_LOCAL_FILES_ONLY")
    stt_timeout_seconds: float = Field(0.0, alias="PLATFORM_STT_TIMEOUT_SECONDS")
    stt_concurrency_limit: int = Field(0, alias="PLATFORM_STT_CONCURRENCY_LIMIT")

    assisted_evolution_enabled: bool = Field(False, alias="PLATFORM_ASSISTED_EVOLUTION_ENABLED")
    evolution_execution_allowed: bool = Field(False, alias="PLATFORM_EVOLUTION_EXECUTION_ALLOWED")
    human_approval_required: bool = Field(True, alias="PLATFORM_EVOLUTION_HUMAN_APPROVAL_REQUIRED")

    @field_validator("invitation_secret")
    @classmethod
    def validate_secret(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError("PLATFORM_INVITATION_TOKEN_SECRET must contain at least 32 characters")
        return value

    @model_validator(mode="after")
    def secure_modes(self):
        provenance = resolve_build_provenance(
            platform_release_sha=self.platform_release_sha,
            railway_git_commit_sha=self.railway_git_commit_sha,
        )
        self.release_sha = provenance.build_sha or "unknown"
        self._release_sha_source = provenance.source
        if self.environment == "production" and self.demo_headers_enabled:
            raise ValueError("DEMO_IDENTITY_HEADERS_FORBIDDEN_IN_PRODUCTION")
        if self.environment == "production":
            if not self.release_sha.strip() or self.release_sha.strip().lower() in {"local", "unknown", "dev"}:
                raise ValueError("PRODUCTION_RELEASE_SHA_REQUIRED")
        if self.environment in {"staging", "production"} and self.invitation_secret == _DEVELOPMENT_INVITATION_SECRET:
            raise ValueError("INVITATION_SECRET_DEFAULT_FORBIDDEN_IN_STAGING_PRODUCTION")
        if self.platform_invitation_enabled:
            if len(self.platform_invitation_secret.strip()) < 32:
                raise ValueError("PLATFORM_USER_INVITATION_SECRET_TOO_SHORT")
            if self.platform_invitation_ttl_hours < 1 or self.platform_invitation_ttl_hours > 168:
                raise ValueError("PLATFORM_USER_INVITATION_TTL_OUT_OF_RANGE")
            allowed_roles = {
                item.strip().lower()
                for item in self.platform_invitation_allowed_roles.split(",")
                if item.strip()
            }
            if not allowed_roles or not allowed_roles.issubset({"member", "admin"}):
                raise ValueError("PLATFORM_USER_INVITATION_ALLOWED_ROLES_INVALID")
            if (
                self.environment in {"staging", "production"}
                and not self.platform_invitation_base_url.strip().lower().startswith("https://")
            ):
                raise ValueError("PLATFORM_USER_INVITATION_HTTPS_REQUIRED")
        if (
            self.platform_activation_rate_limit_window_seconds < 1
            or self.platform_activation_rate_limit_window_seconds > 3600
            or self.platform_activation_status_rate_limit_per_window < 1
            or self.platform_activation_status_rate_limit_per_window > 10000
            or self.platform_activation_accept_rate_limit_per_window < 1
            or self.platform_activation_accept_rate_limit_per_window > 10000
            or self.platform_activation_max_body_bytes < 1024
            or self.platform_activation_max_body_bytes > 1024 * 1024
        ):
            raise ValueError("PLATFORM_ACTIVATION_SECURITY_LIMITS_INVALID")
        try:
            for raw_cidr in self.platform_activation_trusted_proxy_cidrs.split(","):
                raw_cidr = raw_cidr.strip()
                if raw_cidr:
                    ipaddress.ip_network(raw_cidr, strict=False)
        except ValueError as exc:
            raise ValueError("PLATFORM_ACTIVATION_TRUSTED_PROXY_CIDRS_INVALID") from exc
        if (
            self.platform_invitation_enabled
            and self.environment in {"staging", "production"}
            and self.platform_activation_rate_limit_backend != "external"
        ):
            raise ValueError("PLATFORM_ACTIVATION_DISTRIBUTED_RATE_LIMIT_REQUIRED")
        if self.auth_mode == "oidc_introspection":
            required = [
                self.oidc_issuer, self.oidc_audience, self.oidc_introspection_endpoint,
                self.oidc_introspection_client_id, self.oidc_introspection_client_secret,
            ]
            if not all(required):
                raise ValueError("OIDC_CONFIGURATION_INCOMPLETE")
        if self.auth_mode == "native_or_oidc":
            required = [
                self.oidc_issuer,
                self.oidc_audience,
                self.oidc_introspection_endpoint,
                self.oidc_introspection_client_id,
                self.oidc_introspection_client_secret,
            ]
            if not all(required):
                raise ValueError("OIDC_CONFIGURATION_INCOMPLETE")
        if self.auth_mode in {"native_session", "native_or_oidc"}:
            if len(self.native_auth_pepper) < 32:
                raise ValueError("NATIVE_AUTH_PEPPER_TOO_SHORT")
            if len(self.native_session_secret) < 32:
                raise ValueError("NATIVE_SESSION_SECRET_TOO_SHORT")
            if (
                self.environment in {"staging", "production"}
                and len(self.native_bootstrap_secret) < 32
            ):
                raise ValueError("NATIVE_BOOTSTRAP_SECRET_TOO_SHORT")
            if not self.native_session_cookie_name.strip():
                raise ValueError("NATIVE_SESSION_COOKIE_NAME_REQUIRED")
            if (
                self.native_session_cookie_name.startswith("__Host-")
                and not self.native_session_cookie_secure
                and self.environment in {"staging", "production"}
            ):
                raise ValueError("NATIVE_HOST_COOKIE_REQUIRES_SECURE")
            if self.native_session_cookie_samesite == "none" and not self.native_session_cookie_secure:
                raise ValueError("NATIVE_SAMESITE_NONE_REQUIRES_SECURE")
            if self.environment in {"staging", "production"} and not self.native_session_cookie_secure:
                raise ValueError("NATIVE_SESSION_COOKIE_SECURE_REQUIRED")
            if self.native_session_ttl_hours < 1 or self.native_session_ttl_hours > 168:
                raise ValueError("NATIVE_SESSION_TTL_INVALID")
            if self.native_password_min_length < 12:
                raise ValueError("NATIVE_PASSWORD_MIN_LENGTH_TOO_LOW")
            if self.native_password_reset_ttl_minutes < 5 or self.native_password_reset_ttl_minutes > 120:
                raise ValueError("NATIVE_PASSWORD_RESET_TTL_INVALID")
            if self.native_password_reset_base_url and not self.native_password_reset_base_url.startswith("https://"):
                if self.environment in {"staging", "production"}:
                    raise ValueError("NATIVE_PASSWORD_RESET_BASE_URL_REQUIRES_HTTPS")
            if self.environment in {"staging", "production"}:
                if not self.native_password_reset_base_url.strip():
                    raise ValueError("NATIVE_PASSWORD_RESET_BASE_URL_REQUIRED")
                if not self.resend_api_key.strip():
                    raise ValueError("RESEND_API_KEY_REQUIRED_FOR_NATIVE_PASSWORD_RESET")
                if "@" not in self.resend_from:
                    raise ValueError("RESEND_FROM_INVALID")
            if self.native_login_max_failures < 3 or self.native_login_max_failures > 20:
                raise ValueError("NATIVE_LOGIN_MAX_FAILURES_INVALID")
            if self.native_login_lock_minutes < 1 or self.native_login_lock_minutes > 1440:
                raise ValueError("NATIVE_LOGIN_LOCK_MINUTES_INVALID")
        if (
            self.document_ingestion_max_archive_entries < 1
            or self.document_ingestion_max_total_uncompressed_bytes < 1
            or self.document_ingestion_max_member_bytes < 1
            or self.document_ingestion_docx_max_xml_bytes < 1
            or self.document_ingestion_max_member_bytes
            > self.document_ingestion_max_total_uncompressed_bytes
            or self.document_ingestion_docx_max_xml_bytes
            > self.document_ingestion_max_member_bytes
        ):
            raise ValueError("DOCUMENT_INGESTION_LIMIT_RELATION_INVALID")
        if self.access_gate_ttl_seconds < 60 or self.access_gate_ttl_seconds > 3600:
            raise ValueError("ACCESS_GATE_TTL_INVALID")
        if self.access_gate_enabled:
            hashes = [
                item.strip().lower()
                for item in self.access_gate_code_hashes.split(",")
                if item.strip()
            ]
            if not hashes or any(
                len(item) != 64 or any(ch not in "0123456789abcdef" for ch in item)
                for item in hashes
            ):
                raise ValueError("ACCESS_GATE_CODE_HASHES_INVALID")
            if len(self.access_gate_signing_secret) < 32:
                raise ValueError("ACCESS_GATE_SIGNING_SECRET_TOO_SHORT")
            if self.environment == "production" and not self.access_gate_tenant_id.strip():
                raise ValueError("ACCESS_GATE_TENANT_ID_REQUIRED_IN_PRODUCTION")
        admin_emails = [
            item.strip().lower()
            for item in self.admin_email_allowlist.split(",")
            if item.strip()
        ]
        if not admin_emails or any("@" not in item for item in admin_emails):
            raise ValueError("ADMIN_EMAIL_ALLOWLIST_INVALID")
        if self.artifact_storage_backend == "s3":
            if not self.artifact_storage_bucket.strip() or not self.artifact_storage_region.strip():
                raise ValueError("S3_STORAGE_CONFIGURATION_INCOMPLETE")
            if not self.artifact_storage_access_key_id.strip() or not self.artifact_storage_secret_access_key:
                raise ValueError("S3_STORAGE_CREDENTIALS_REQUIRED")
            if self.artifact_storage_endpoint_url and not self.artifact_storage_endpoint_url.lower().startswith("https://"):
                raise ValueError("S3_STORAGE_TLS_REQUIRED")
            if self.artifact_storage_sse == "aws:kms" and not self.artifact_storage_kms_key_id.strip():
                raise ValueError("S3_KMS_KEY_REQUIRED")
            if ".." in self.artifact_storage_prefix.replace("\\", "/").split("/"):
                raise ValueError("S3_STORAGE_PREFIX_INVALID")
        if self.environment == "production" and self.artifacts_enabled and self.artifact_storage_backend != "s3":
            raise ValueError("PRODUCTION_ARTIFACT_STORAGE_MUST_BE_DURABLE")
        if self.billing_usd_brl <= 0:
            raise ValueError("BILLING_USD_BRL_INVALID")
        if self.billing_http_timeout_seconds <= 0 or self.billing_http_timeout_seconds > 60:
            raise ValueError("BILLING_HTTP_TIMEOUT_INVALID")
        for raw, code in (
            (self.billing_plan_catalog_json, "BILLING_PLAN_CATALOG_INVALID_JSON"),
            (self.billing_topup_catalog_json, "BILLING_TOPUP_CATALOG_INVALID_JSON"),
        ):
            try:
                import json as _json
                parsed = _json.loads(raw or "{}")
            except Exception as exc:
                raise ValueError(code) from exc
            if not isinstance(parsed, dict):
                raise ValueError(code)
        if self.billing_live_mode_enabled and self.environment != "production":
            raise ValueError("BILLING_LIVE_MODE_FORBIDDEN_OUTSIDE_PRODUCTION")
        if self.billing_enabled:
            if self.billing_provider != "asaas":
                raise ValueError("BILLING_PROVIDER_REQUIRED")
            if not self.asaas_api_key.strip():
                raise ValueError("ASAAS_API_KEY_REQUIRED")
            if len(self.asaas_webhook_token.strip()) < 24:
                raise ValueError("ASAAS_WEBHOOK_TOKEN_TOO_SHORT")
            if not self.billing_checkout_success_url.strip():
                raise ValueError("BILLING_CHECKOUT_SUCCESS_URL_REQUIRED")
            if self.environment in {"staging", "production"} and not self.billing_checkout_success_url.lower().startswith("https://"):
                raise ValueError("BILLING_CHECKOUT_SUCCESS_URL_REQUIRES_HTTPS")
            if not self.asaas_api_base_url.lower().startswith("https://"):
                raise ValueError("ASAAS_API_BASE_URL_REQUIRES_HTTPS")
            if self.environment == "staging":
                if self.billing_live_mode_enabled:
                    raise ValueError("BILLING_LIVE_MODE_FORBIDDEN_IN_STAGING")
                if "sandbox" not in self.asaas_api_base_url.lower():
                    raise ValueError("BILLING_STAGING_REQUIRES_SANDBOX_PROVIDER")
            if self.environment == "production":
                if not self.billing_live_mode_enabled:
                    raise ValueError("BILLING_PRODUCTION_REQUIRES_EXPLICIT_LIVE_MODE")
                if self.asaas_api_base_url.rstrip("/") != "https://api.asaas.com/v3":
                    raise ValueError("BILLING_PRODUCTION_PROVIDER_BASE_INVALID")
        if not self.github_read_only:
            raise ValueError("GITHUB_WRITE_MODE_FORBIDDEN")
        if self.github_enabled and not self.github_allowed_repositories.strip():
            raise ValueError("GITHUB_ALLOWED_REPOSITORIES_REQUIRED")
        if self.github_enabled and self.github_api_base.rstrip("/") != "https://api.github.com":
            raise ValueError("GITHUB_API_BASE_FORBIDDEN")
        if (
            self.github_http_timeout_seconds <= 0
            or self.github_max_file_bytes <= 0
            or self.github_max_tree_entries <= 0
            or self.github_snapshot_max_files <= 0
            or self.github_snapshot_max_chars <= 0
        ):
            raise ValueError("GITHUB_READ_LIMITS_INVALID")
        if self.voice_enabled and self.voice_provider == "disabled":
            raise ValueError("VOICE_PROVIDER_REQUIRED")
        if self.tts_enabled and self.tts_provider == "disabled":
            raise ValueError("TTS_PROVIDER_REQUIRED")
        if self.tts_http_timeout_seconds <= 0:
            raise ValueError("TTS_TIMEOUT_INVALID")
        if self.tts_max_chars <= 0 or self.tts_max_chars > 4096:
            raise ValueError("TTS_MAX_CHARS_INVALID")
        if (
            self.tts_user_rate_limit_per_minute <= 0
            or self.tts_tenant_rate_limit_per_minute <= 0
            or self.tts_message_rate_limit_per_minute <= 0
        ):
            raise ValueError("TTS_RATE_LIMIT_INVALID")
        if not self.tts_cache_path.strip():
            raise ValueError("TTS_CACHE_PATH_REQUIRED")
        if self.large_document_pipeline_enabled:
            if self.knowledge_large_document_max_upload_bytes <= 0:
                raise ValueError("KNOWLEDGE_MAX_UPLOAD_BYTES_INVALID")
            if self.knowledge_large_document_auto_process_bytes < 0:
                raise ValueError("KNOWLEDGE_AUTO_PROCESS_BYTES_INVALID")
            if self.knowledge_large_document_max_pdf_pages <= 0:
                raise ValueError("KNOWLEDGE_MAX_PDF_PAGES_INVALID")
            if self.knowledge_chunk_target_chars < 1_000:
                raise ValueError("KNOWLEDGE_CHUNK_TARGET_CHARS_INVALID")
            if (
                self.knowledge_chunk_overlap_chars < 0
                or self.knowledge_chunk_overlap_chars >= self.knowledge_chunk_target_chars
            ):
                raise ValueError("KNOWLEDGE_CHUNK_OVERLAP_CHARS_INVALID")
            if self.knowledge_retrieval_top_k <= 0:
                raise ValueError("KNOWLEDGE_RETRIEVAL_TOP_K_INVALID")
        if self.stt_enabled and self.stt_provider == "disabled":
            raise ValueError("STT_PROVIDER_REQUIRED")
        if self.stt_max_upload_bytes <= 0:
            raise ValueError("STT_MAX_UPLOAD_BYTES_INVALID")
        if not self.stt_model_cache_dir.strip():
            raise ValueError("STT_MODEL_CACHE_DIR_REQUIRED")
        if self.stt_enabled and self.stt_timeout_seconds <= 0:
            raise ValueError("STT_TIMEOUT_SECONDS_REQUIRED")
        if self.stt_enabled and self.stt_concurrency_limit <= 0:
            raise ValueError("STT_CONCURRENCY_LIMIT_REQUIRED")
        if self.environment == "production" and self.stt_enabled and not self.stt_local_files_only:
            raise ValueError("STT_PRODUCTION_REQUIRES_PREWARMED_LOCAL_MODEL")
        allowed_languages = {
            item.strip().lower()
            for item in self.stt_allowed_languages.split(",")
            if item.strip()
        }
        if not allowed_languages or not allowed_languages.issubset({"pt", "en", "es"}):
            raise ValueError("STT_ALLOWED_LANGUAGES_INVALID")
        if self.llm_provider_failover_enabled:
            raise ValueError("LLM_PROVIDER_FAILOVER_FORBIDDEN_UNTIL_GOVERNED")
        if self.llm_auto_route_enabled:
            raise ValueError("LLM_AUTO_ROUTE_FORBIDDEN_UNTIL_GOVERNED")
        if self.founder_council_min_configured_providers < 2:
            raise ValueError("FOUNDER_COUNCIL_REQUIRES_AT_LEAST_TWO_PROVIDERS")
        if self.anthropic_max_tokens <= 0 or self.google_max_output_tokens <= 0:
            raise ValueError("LLM_PROVIDER_MAX_TOKENS_INVALID")
        if self.llm_http_timeout_seconds <= 0:
            raise ValueError("PLATFORM_LLM_HTTP_TIMEOUT_SECONDS_INVALID")
        if self.evolution_execution_allowed:
            raise ValueError("AUTOEVOLUTION_EXECUTION_FORBIDDEN_BY_DEFAULT")
        return self

@lru_cache
def get_settings() -> Settings:
    return Settings()
