from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Decision(StrEnum):
    EXACT = "EXACT"
    COMPATIBLE = "COMPATIBLE"
    INCOMPATIBLE = "INCOMPATIBLE"
    INCONCLUSIVE = "INCONCLUSIVE"


class CompletenessStatus(StrEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"


class AccessMode(StrEnum):
    DIRECT = "DIRECT"
    INHERITED = "INHERITED"
    SET_ROLE = "SET_ROLE"
    ADMIN_CAPABILITY = "ADMIN_CAPABILITY"


class CollectorSessionProfile(FrozenModel):
    session_profile_id: str = "EFATA-COLLECTOR-SESSION-1"
    session_profile_version: str = "1"
    search_path: str = "pg_catalog"
    timezone: str = "UTC"
    datestyle: str = "ISO, YMD"
    intervalstyle: str = "postgres"
    standard_conforming_strings: str = "on"
    extra_float_digits: str = "3"
    bytea_output: str = "hex"
    transaction_isolation: str = "repeatable read"
    transaction_read_only: str = "on"
    statement_timeout_ms: int = Field(default=5000, ge=1, le=60000)
    lock_timeout_ms: int = Field(default=2000, ge=1, le=60000)
    idle_in_transaction_session_timeout_ms: int = Field(default=15000, ge=1, le=120000)


class CaptureTargetBinding(FrozenModel):
    binding_version: str = "1"
    fixture_runtime_id: str
    connection_binding_id: str
    expected_fixture_nonce: str
    expected_database_name_sha256: str
    expected_collector_principal: str
    expected_postgres_major: int = 16
    expected_transport: Literal["UNIX_SOCKET"] = "UNIX_SOCKET"


class ConnectionAttestation(FrozenModel):
    attestation_version: str = "1"
    fixture_runtime_id: str
    connection_binding_id: str
    expected_fixture_nonce: str
    observed_fixture_nonce: str
    expected_database_name_sha256: str
    observed_database_name_sha256: str
    expected_principal: str
    session_user: str
    current_user: str
    expected_postgres_major: int
    observed_postgres_major: int
    transport: Literal["UNIX_SOCKET"]
    inet_client_addr: str | None
    inet_client_port: int | None
    inet_server_addr: str | None
    inet_server_port: int | None
    backend_pid: int
    transaction_read_only: bool
    transaction_isolation: str
    attestation_sha256: str


class CaptureProvenance(FrozenModel):
    provenance_version: str = "1"
    capture_id: str
    collector_execution_id: str
    database_target_id: str
    environment: Literal["test"]
    database_name_sha256: str
    fixture_runtime_id: str
    connection_binding_id: str
    postgres_major_version: int
    postgres_full_version: str
    backend_pid: int
    transaction_started_at_utc: str
    transaction_snapshot_ref: str
    collector_version: str
    query_pack_version: str
    query_pack_sha256: str
    session_profile_version: str
    session_profile_sha256: str
    included_namespaces: tuple[str, ...]
    captured_at_utc: str
    connection_attestation_sha256: str


class CaptureCompletenessReport(FrozenModel):
    completeness_version: str = "1"
    completeness_proof_mode: Literal["LOCAL_FIXTURE_GROUND_TRUTH_V1"]
    required_catalog_surfaces: tuple[str, ...]
    observed_catalog_surfaces: tuple[str, ...]
    failed_catalog_surfaces: tuple[str, ...] = ()
    missing_ground_truth_objects: tuple[str, ...] = ()
    unexpected_ground_truth_objects: tuple[str, ...] = ()
    unclassified_namespaces: tuple[str, ...] = ()
    unclassified_objects: tuple[str, ...] = ()
    unclassified_principals: tuple[str, ...] = ()
    cross_reference_failures: tuple[str, ...] = ()
    status: CompletenessStatus
    reason_codes: tuple[str, ...] = ()


class StructuralManifest(FrozenModel):
    manifest_spec_version: str = "EFATA-SCHEMA-FP-1"
    database_family: Literal["postgresql"] = "postgresql"
    postgres_major_version: int = 16
    included_namespaces: tuple[str, ...]
    namespaces: tuple[dict[str, Any], ...] = ()
    relations: tuple[dict[str, Any], ...] = ()
    columns: tuple[dict[str, Any], ...] = ()
    constraints: tuple[dict[str, Any], ...] = ()
    indexes: tuple[dict[str, Any], ...] = ()
    types: tuple[dict[str, Any], ...] = ()
    sequences: tuple[dict[str, Any], ...] = ()
    functions: tuple[dict[str, Any], ...] = ()
    views: tuple[dict[str, Any], ...] = ()
    triggers: tuple[dict[str, Any], ...] = ()
    rls_policies: tuple[dict[str, Any], ...] = ()
    extensions: tuple[dict[str, Any], ...] = ()
    alembic_revisions: tuple[str, ...] = ()


class SecurityManifest(FrozenModel):
    manifest_spec_version: str = "EFATA-DB-SECURITY-COMPAT-1"
    postgres_major_version: int = 16
    database_acl: tuple[dict[str, Any], ...] = ()
    roles: tuple[dict[str, Any], ...] = ()
    memberships: tuple[dict[str, Any], ...] = ()
    schema_acls: tuple[dict[str, Any], ...] = ()
    relation_acls: tuple[dict[str, Any], ...] = ()
    sequence_acls: tuple[dict[str, Any], ...] = ()
    function_acls: tuple[dict[str, Any], ...] = ()
    default_acls: tuple[dict[str, Any], ...] = ()
    security_definer_functions: tuple[dict[str, Any], ...] = ()


class CaptureBundle(FrozenModel):
    bundle_version: str = "1"
    provenance: CaptureProvenance
    connection_attestation: ConnectionAttestation
    structural_manifest: StructuralManifest
    security_manifest: SecurityManifest
    completeness: CaptureCompletenessReport
    terminal_status: Literal["CAPTURED", "INCONCLUSIVE"]


class PrincipalRule(FrozenModel):
    principal_class: str
    physical_role_names: tuple[str, ...]
    min_count: int = Field(default=0, ge=0)
    max_count: int = Field(default=1, ge=1)
    aliases_allowed: bool = False
    required_true_attributes: tuple[str, ...] = ()
    forbidden_true_attributes: tuple[str, ...] = ()


class SchemaCompatibilityProfile(FrozenModel):
    profile_id: str
    profile_version: str
    accepted_alembic_revisions: tuple[str, ...] = ()
    required_namespaces: tuple[str, ...] = ()
    required_objects: tuple[str, ...] = ()
    forbidden_objects: tuple[str, ...] = ()
    allowed_extra_objects: tuple[str, ...] = ()
    allowed_extra_patterns: tuple[str, ...] = ()
    allowed_recommended_indexes: tuple[str, ...] = ()


class DatabaseSecurityCompatibilityProfile(FrozenModel):
    profile_id: str
    profile_version: str
    principal_rules: tuple[PrincipalRule, ...] = ()
    forbidden_role_attributes: tuple[str, ...] = ()
    forbidden_public_privileges: tuple[str, ...] = ()
    required_security_facts: tuple[str, ...] = ()
    forbidden_security_facts: tuple[str, ...] = ()


class Delta(FrozenModel):
    code: str
    object_id: str
    expected: Any | None = None
    observed: Any | None = None
    severity: Literal["INFO", "WARNING", "ERROR"] = "ERROR"


class CompatibilityResult(FrozenModel):
    decision: Decision
    reason_codes: tuple[str, ...] = ()
    deltas: tuple[Delta, ...] = ()
    profile_sha256: str
    compatibility_signature_sha256: str


class DatabaseCompatibilityDecision(FrozenModel):
    schema_decision: Decision
    security_decision: Decision
    overall_decision: Decision
    structural_manifest_sha256: str
    security_manifest_sha256: str
    logical_schema_sha256: str
    physical_schema_sha256: str
    logical_security_sha256: str
    schema_profile_sha256: str
    security_profile_sha256: str
    query_pack_sha256: str
    session_profile_sha256: str
    reason_codes: tuple[str, ...] = ()
    evaluator_version: str = "EFATA-SCHEMA-EVALUATOR-1"


class FixturePrivilegeTransitionEvidence(FrozenModel):
    evidence_version: str = "1"
    fixture_runtime_id: str
    bootstrap_principal_class: str
    bootstrap_connection_closed: bool
    bootstrap_reconnect_denied: bool
    collector_principal_class: str
    collector_session_user: str
    collector_current_user: str
    privileged_set_role_attempt: Literal["DENIED"]
    business_row_select_attempt: Literal["DENIED"]
    write_attempts: tuple[str, ...]
    connection_attestation_sha256: str
    captured_at_trusted: str


class RoleMembershipProofEdge(FrozenModel):
    from_role: str
    to_role: str
    inherit_option: bool
    set_option: bool
    admin_option: bool
    grantor: str | None = None


class AuthorityProof(FrozenModel):
    principal: str
    privilege: str
    access_mode: AccessMode
    initial_role: str
    effective_role_state: str
    proof_path: tuple[RoleMembershipProofEdge, ...] = ()
    source_object: str | None = None
    source_acl: str | None = None


class AuthorityEvaluation(FrozenModel):
    principal: str
    summary: tuple[str, ...]
    proofs: tuple[AuthorityProof, ...]
