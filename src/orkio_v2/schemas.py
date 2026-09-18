import unicodedata
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from typing import Literal

class AdminVoiceAssignmentUpsert(BaseModel):
    voice_catalog_id: str = Field(min_length=1, max_length=64)
    locale: str = Field("pt-BR", min_length=2, max_length=24)
    delivery_modes: list[Literal["REALTIME_STREAM", "MESSAGE_PLAYBACK", "VOICE_MESSAGE"]] = Field(default_factory=list)
    presentation_label: Literal["MASCULINA", "FEMININA", "NEUTRA", "NAO_DEFINIDA"] = "NAO_DEFINIDA"
    timbre_label: str | None = Field(default=None, max_length=80)
    energy_label: str | None = Field(default=None, max_length=80)


class AdminVoiceAssignmentValidationUpdate(BaseModel):
    validation_status: Literal["VALIDATED", "FAILED"]
    evidence_ref: str = Field(min_length=8, max_length=500)


class AdminVoiceAssignmentActivationRequest(BaseModel):
    evidence_ref: str = Field(min_length=8, max_length=500)

class ThreadCreate(BaseModel):
    title: str = Field("Nova conversa", max_length=240)

class ThreadTitleUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=240)

class MessageCreate(BaseModel):
    content: str = Field(min_length=1, max_length=100000)
    agent: str = Field("Josué", max_length=160)


class LargePasteIntakeRequest(BaseModel):
    content: str = Field(min_length=1, max_length=5_000_000)
    title: str | None = Field(default=None, max_length=240)

class InvitationCreate(BaseModel):
    email: EmailStr
    role: Literal["moderator","participant","viewer"] = "participant"
    history_access: Literal["from_join","full_thread"] = "from_join"
    can_view_attachments: bool = False
    can_download_artifacts: bool = False
    can_upload_files: bool = False
    can_generate_artifacts: bool = False

class InvitationOut(BaseModel):
    invitation_id: str
    invitation_url: str
    expires_at: datetime

class InvitationAccept(BaseModel):
    token: str = Field(min_length=32)



class PlatformInvitationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    role: Literal["member", "admin"] = "member"


class PlatformInvitationTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=32, max_length=1024)


class PlatformInvitationAcceptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=32, max_length=1024)
    display_name: str = Field(min_length=2, max_length=200)
    password: str = Field(min_length=12, max_length=256)
    password_confirm: str = Field(min_length=12, max_length=256)


class PlatformInvitationOut(BaseModel):
    invitation_id: str
    invited_email: EmailStr
    role: str
    state: Literal["PENDING", "ACCEPTED", "REVOKED", "EXPIRED"]
    delivery_status: Literal["PENDING", "ACCEPTED_BY_PROVIDER", "DELIVERY_FAILED"]
    delivery_attempts: int
    delivery_generation: int
    expires_at: datetime
    accepted_at: datetime | None = None
    revoked_at: datetime | None = None
    provider_message_id: str | None = None
    delivery_error_code: str | None = None


class PlatformInvitationStatusOut(BaseModel):
    status: Literal["PENDING", "ACCEPTED", "REVOKED", "EXPIRED"]
    delivery_status: Literal["PENDING", "ACCEPTED_BY_PROVIDER", "DELIVERY_FAILED"]
    expires_at: datetime
    email_hint: str


class PlatformInvitationAcceptOut(BaseModel):
    status: Literal["ACCEPTED_LOGIN_REQUIRED"]
    tenant_id: str
    role: str


class AdminMembershipUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["member", "admin"] | None = None
    active: bool | None = None

    @model_validator(mode="after")
    def at_least_one_change(self):
        if self.role is None and self.active is None:
            raise ValueError("MEMBERSHIP_UPDATE_EMPTY")
        return self


class AdminSessionRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field("admin_revocation", min_length=3, max_length=120)

class EvolutionProposalCreate(BaseModel):
    title: str
    issue_map: dict
    patch_plan: dict
    diff_preview: str = ""
    risk_assessment: dict
    rollback_plan: dict
    smoke_plan: dict


class GitHubSnapshotRequest(BaseModel):
    repository: str = Field(min_length=3, max_length=240)
    paths: list[str] = Field(default_factory=list, max_length=20)

class PythonExecuteRequest(BaseModel):
    code: str = Field(min_length=1, max_length=100000)


class ExternalReadRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)



class AccessCodeValidateRequest(BaseModel):
    code: str = Field(min_length=4, max_length=128)


class HyperCocreatorOnboardingComplete(BaseModel):
    grant: str = Field(min_length=32, max_length=4096)
    co_creator_name: str = Field(min_length=2, max_length=64)
    onboarding_goal: str | None = Field(default=None, max_length=240)


class HyperCocreatorProfileUpdate(BaseModel):
    co_creator_name: str = Field(min_length=2, max_length=64)


class NativeBootstrapOwnerRequest(BaseModel):
    bootstrap_secret: str = Field(min_length=32, max_length=512)
    tenant_id: str = Field("patroai", min_length=3, max_length=64)
    tenant_name: str = Field("Grupo PatroAI", min_length=2, max_length=200)
    email: EmailStr
    display_name: str = Field(min_length=2, max_length=200)
    password: str = Field(min_length=12, max_length=256)


class NativeLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    tenant_id: str | None = Field(default=None, max_length=64)
    return_path: str | None = Field(default=None, max_length=512)


class NativeAdminOtpStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class NativeAdminOtpStartOut(BaseModel):
    status: str
    challenge_token: str
    expires_in_seconds: int


class NativeAdminOtpVerifyRequest(BaseModel):
    challenge_token: str = Field(min_length=32, max_length=512)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class NativeRegisterWithGrantRequest(BaseModel):
    grant: str = Field(min_length=32, max_length=4096)
    email: EmailStr
    display_name: str = Field(min_length=2, max_length=200)
    password: str = Field(min_length=12, max_length=256)
    co_creator_name: str = Field(min_length=2, max_length=64)
    onboarding_goal: str | None = Field(default=None, max_length=240)


class NativeForgotPasswordRequest(BaseModel):
    email: EmailStr


class NativeForgotPasswordOut(BaseModel):
    status: str
    reset_token: str | None = None


class NativeResetPasswordRequest(BaseModel):
    token: str = Field(min_length=32, max_length=512)
    password: str = Field(min_length=12, max_length=256)
    password_confirm: str = Field(min_length=12, max_length=256)


class NativeSessionOut(BaseModel):
    authenticated: bool
    status: str | None = None
    user_id: str | None = None
    tenant_id: str | None = None
    email: EmailStr | None = None
    roles: list[str] = Field(default_factory=list)
    challenge_token: str | None = None
    claim_token: str | None = None
    verification_token: str | None = None
    recovery_codes: list[str] = Field(default_factory=list)


class NativeRegistrationOut(BaseModel):
    status: str
    verification_token: str | None = None
    claim_token: str | None = None


class NativeMfaEnrollStartRequest(BaseModel):
    challenge_token: str = Field(min_length=32, max_length=512)


class NativeMfaEnrollStartOut(BaseModel):
    secret: str
    otpauth_uri: str


class NativeMfaEnrollConfirmRequest(BaseModel):
    challenge_token: str = Field(min_length=32, max_length=512)
    code: str = Field(min_length=6, max_length=8)


class NativeMfaVerifyRequest(BaseModel):
    challenge_token: str = Field(min_length=32, max_length=512)
    code: str | None = Field(default=None, min_length=6, max_length=8)
    recovery_code: str | None = Field(default=None, min_length=6, max_length=32)


class NativeReauthenticateRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str | None = Field(default=None, min_length=6, max_length=8)
    recovery_code: str | None = Field(default=None, min_length=6, max_length=32)


class NativeAccountActionRequest(BaseModel):
    token: str = Field(min_length=32, max_length=512)


class NativeAccountRecoveryRequest(BaseModel):
    token: str = Field(min_length=32, max_length=512)
    password: str = Field(min_length=12, max_length=256)
    password_confirm: str = Field(min_length=12, max_length=256)


class NativeSessionRecordOut(BaseModel):
    id: str
    current: bool
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    user_agent: str
    ip_prefix: str
    mfa_verified: bool = False

class _AuditRequestBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validate_audit_marker(value: str | None) -> str | None:
    if value is None:
        return None
    raw = value.encode("utf-8")
    if not raw or len(raw) > 512:
        raise ValueError("AUDIT_MARKER_BOUNDS_INVALID")
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        raise ValueError("AUDIT_MARKER_CONTROL_CHAR_FORBIDDEN")
    return value


class AuditFileInspectRequest(_AuditRequestBase):
    root_id: str = Field(min_length=1, max_length=64)
    relative_path: str = Field(min_length=1, max_length=1024)
    operation: Literal["metadata", "read_text", "search_marker"]
    offset: int = Field(default=0, ge=0, le=100_000_000)
    max_bytes: int = Field(default=16_000, ge=1, le=64_000)
    marker: str | None = None
    max_matches: int = Field(default=256, ge=1, le=256)

    @field_validator("marker")
    @classmethod
    def validate_marker(cls, value: str | None) -> str | None:
        return _validate_audit_marker(value)

    @model_validator(mode="after")
    def validate_operation_contract(self):
        if self.operation == "search_marker" and self.marker is None:
            raise ValueError("AUDIT_MARKER_REQUIRED")
        if self.operation != "search_marker" and self.marker is not None:
            raise ValueError("AUDIT_MARKER_NOT_ALLOWED")
        return self


class AuditArchiveInspectRequest(_AuditRequestBase):
    artifact_id: str | None = Field(default=None, min_length=1, max_length=160)
    root_id: str | None = Field(default=None, min_length=1, max_length=64)
    relative_path: str | None = Field(default=None, min_length=1, max_length=1024)
    operation: Literal["manifest", "file_metadata", "read_text_member", "hash_member"]
    member: str | None = Field(default=None, min_length=1, max_length=1024)
    offset: int = Field(default=0, ge=0, le=100_000_000)
    max_bytes: int = Field(default=16_000, ge=1, le=64_000)
    manifest_offset: int = Field(default=0, ge=0, le=100_000)
    manifest_limit: int = Field(default=100, ge=1, le=512)

    @model_validator(mode="after")
    def validate_archive_contract(self):
        artifact_branch = self.artifact_id is not None
        root_branch = self.root_id is not None or self.relative_path is not None
        if artifact_branch == root_branch:
            raise ValueError("AUDIT_ARCHIVE_SOURCE_REFERENCE_REQUIRED")
        if root_branch and (self.root_id is None or self.relative_path is None):
            raise ValueError("AUDIT_ARCHIVE_ROOT_REFERENCE_INCOMPLETE")

        member_required = self.operation in {
            "file_metadata",
            "read_text_member",
            "hash_member",
        }
        if member_required and self.member is None:
            raise ValueError("AUDIT_ARCHIVE_MEMBER_REQUIRED")
        if not member_required and self.member is not None:
            raise ValueError("AUDIT_ARCHIVE_MEMBER_NOT_ALLOWED")
        return self


class AuditRuntimeFileSha256Request(_AuditRequestBase):
    module_id: str = Field(min_length=1, max_length=160)


class AuditRuntimeSearchMarkerRequest(_AuditRequestBase):
    module_id: str = Field(min_length=1, max_length=160)
    marker: str
    max_scan_bytes: int = Field(default=1_000_000, ge=1, le=1_000_000)
    max_matches: int = Field(default=256, ge=1, le=256)

    @field_validator("marker")
    @classmethod
    def validate_marker(cls, value: str) -> str:
        return _validate_audit_marker(value) or ""
