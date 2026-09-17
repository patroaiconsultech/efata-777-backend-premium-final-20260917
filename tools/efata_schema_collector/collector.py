from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from .canonical import sha256_canonical, sha256_text
from .completeness import build_completeness_report, validate_ground_truth_contract
from .contracts import (
    CaptureBundle,
    CaptureProvenance,
    CaptureTargetBinding,
    CollectorSessionProfile,
    SecurityManifest,
    StructuralManifest,
)
from .function_fingerprint import (
    UnsupportedSecurityFunctionLanguage,
    fingerprint_security_sensitive_function,
)
from .query_pack import QUERY_PACK_SHA256, QUERY_PACK_VERSION, QUERY_SPECS
from .session import (
    apply_and_verify_session_profile,
    begin_readonly_transaction,
)
from .target_binding import verify_connection_attestation

COLLECTOR_VERSION = "EFATA-PG-SCHEMA-COLLECTOR-1-DRAFT-02-R1"


class CaptureError(RuntimeError):
    pass


def _rows_as_dicts(cursor) -> list[dict]:
    columns = [d.name if hasattr(d, "name") else d[0] for d in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _run_query(connection, spec, included_namespaces: tuple[str, ...]) -> list[dict]:
    params = (list(included_namespaces),) if spec.namespace_scoped else ()
    with connection.cursor() as cur:
        cur.execute(spec.sql, params)
        return _rows_as_dicts(cur)


def _sanitize_function_rows(rows: list[dict]) -> tuple[list[dict], list[dict], list[str]]:
    structural: list[dict] = []
    security_definers: list[dict] = []
    failures: list[str] = []
    for row in rows:
        raw = dict(row)
        identity = (
            f'{raw["schema_name"]}.{raw["function_name"]}'
            f'({raw.get("identity_arguments") or ""})'
        )
        try:
            fp, material = fingerprint_security_sensitive_function(raw)
            sanitized = {
                key: value
                for key, value in raw.items()
                if key not in {"prosrc", "probin", "function_definition", "proconfig"}
            }
            sanitized["identity"] = identity
            sanitized["canonical_proconfig"] = material["config"]
            sanitized["function_definition_sha256"] = material["definition_sha256"]
            sanitized["function_fingerprint_sha256"] = fp
            structural.append(sanitized)
            if bool(raw.get("prosecdef")):
                security_definers.append({
                    "identity": identity,
                    "owner_name": raw.get("owner_name"),
                    "language": str(raw.get("language") or "").lower(),
                    "function_definition_sha256": material["definition_sha256"],
                    "function_fingerprint_sha256": fp,
                    "canonical_proconfig": material["config"],
                })
        except UnsupportedSecurityFunctionLanguage:
            # Non-security-definer unsupported functions remain visible as
            # structurally present, but a security-sensitive one fails capture.
            sanitized = {
                key: value
                for key, value in raw.items()
                if key not in {"prosrc", "probin", "function_definition", "proconfig"}
            }
            sanitized["identity"] = identity
            sanitized["function_fingerprint_status"] = "UNSUPPORTED"
            structural.append(sanitized)
            if bool(raw.get("prosecdef")):
                failures.append(
                    f"CAPTURE.SECURITY_SENSITIVE_FUNCTION_LANGUAGE_UNSUPPORTED:{identity}"
                )
    return structural, security_definers, failures


def collect_capture_bundle(
    connection,
    binding: CaptureTargetBinding,
    ground_truth: dict,
    *,
    included_namespaces: tuple[str, ...] = ("public",),
    collector_execution_id: str | None = None,
    database_target_id: str = "local-disposable-pg16",
    session_profile: CollectorSessionProfile | None = None,
) -> CaptureBundle:
    validate_ground_truth_contract(ground_truth)
    if not included_namespaces:
        raise CaptureError("CAPTURE.NO_INCLUDED_NAMESPACE")
    if any(
        ns in {"pg_catalog", "information_schema", "pg_toast"}
        or ns.startswith("pg_temp_")
        or ns.startswith("pg_toast_temp_")
        for ns in included_namespaces
    ):
        raise CaptureError("CAPTURE.SYSTEM_NAMESPACE_FORBIDDEN")

    profile = session_profile or CollectorSessionProfile()
    execution_id = collector_execution_id or str(uuid4())
    capture_id = str(uuid4())
    observed: dict[str, list[dict]] = {}
    observed_surfaces: list[str] = []
    failed_surfaces: list[str] = []

    try:
        begin_readonly_transaction(connection)
        attestation = verify_connection_attestation(connection, binding)
        session_profile_sha = apply_and_verify_session_profile(connection, profile)

        for spec in QUERY_SPECS:
            try:
                observed[spec.name] = _run_query(
                    connection,
                    spec,
                    included_namespaces,
                )
                observed_surfaces.append(spec.name)
            except Exception as exc:
                failed_surfaces.append(spec.name)
                observed[spec.name] = []

        meta_rows = observed.get("meta.snapshot") or []
        if not meta_rows:
            raise CaptureError("CAPTURE.META_SNAPSHOT_UNAVAILABLE")
        meta = meta_rows[0]

        function_rows, security_definers, function_failures = _sanitize_function_rows(
            observed.get("catalog.functions", [])
        )
        if function_failures:
            failed_surfaces.append("catalog.functions")

        relation_acls = observed.get("security.relation_acls", [])
        sequence_acls = [row for row in relation_acls if row.get("relkind") == "S"]
        non_sequence_acls = [row for row in relation_acls if row.get("relkind") != "S"]

        structural = StructuralManifest(
            included_namespaces=tuple(sorted(included_namespaces)),
            namespaces=tuple(observed.get("catalog.namespaces", [])),
            relations=tuple(observed.get("catalog.relations", [])),
            columns=tuple(observed.get("catalog.columns", [])),
            constraints=tuple(observed.get("catalog.constraints", [])),
            indexes=tuple(observed.get("catalog.indexes", [])),
            types=tuple(observed.get("catalog.types", [])),
            sequences=tuple(observed.get("catalog.sequences", [])),
            functions=tuple(function_rows),
            views=tuple(observed.get("catalog.views", [])),
            triggers=tuple(observed.get("catalog.triggers", [])),
            rls_policies=tuple(observed.get("catalog.rls", [])),
            extensions=tuple(observed.get("catalog.extensions", [])),
            alembic_revisions=tuple(
                str(row["version_num"])
                for row in observed.get("migration.alembic_revision", [])
            ),
        )
        security = SecurityManifest(
            database_acl=tuple(observed.get("security.database_acl", [])),
            roles=tuple(observed.get("security.roles", [])),
            memberships=tuple(observed.get("security.memberships", [])),
            schema_acls=tuple(observed.get("security.schema_acls", [])),
            relation_acls=tuple(non_sequence_acls),
            sequence_acls=tuple(sequence_acls),
            function_acls=tuple(observed.get("security.function_acls", [])),
            default_acls=tuple(observed.get("security.default_acls", [])),
            security_definer_functions=tuple(security_definers),
        )
        completeness = build_completeness_report(
            structural,
            security,
            ground_truth,
            observed_surfaces=observed_surfaces,
            failed_surfaces=tuple(sorted(set(failed_surfaces + function_failures))),
        )

        provenance = CaptureProvenance(
            capture_id=capture_id,
            collector_execution_id=execution_id,
            database_target_id=database_target_id,
            environment="test",
            database_name_sha256=attestation.observed_database_name_sha256,
            fixture_runtime_id=attestation.fixture_runtime_id,
            connection_binding_id=attestation.connection_binding_id,
            postgres_major_version=attestation.observed_postgres_major,
            postgres_full_version=str(meta["server_version"]),
            backend_pid=int(meta["backend_pid"]),
            transaction_started_at_utc=str(meta["transaction_started_at"]),
            transaction_snapshot_ref=sha256_text(str(meta["transaction_snapshot"])),
            collector_version=COLLECTOR_VERSION,
            query_pack_version=QUERY_PACK_VERSION,
            query_pack_sha256=QUERY_PACK_SHA256,
            session_profile_version=profile.session_profile_version,
            session_profile_sha256=session_profile_sha,
            included_namespaces=tuple(sorted(included_namespaces)),
            captured_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            connection_attestation_sha256=attestation.attestation_sha256,
        )

        terminal = "CAPTURED" if completeness.status.value == "COMPLETE" else "INCONCLUSIVE"
        bundle = CaptureBundle(
            provenance=provenance,
            connection_attestation=attestation,
            structural_manifest=structural,
            security_manifest=security,
            completeness=completeness,
            terminal_status=terminal,
        )
        return bundle
    finally:
        try:
            connection.rollback()
        except Exception:
            pass
