from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from .canonical import sha256_canonical
from .completeness import (
    observed_security_fact_ids,
    observed_structural_object_ids,
)
from .contracts import (
    CaptureCompletenessReport,
    CompatibilityResult,
    DatabaseCompatibilityDecision,
    DatabaseSecurityCompatibilityProfile,
    Decision,
    Delta,
    SchemaCompatibilityProfile,
    SecurityManifest,
    StructuralManifest,
)
from .query_pack import QUERY_PACK_SHA256


EVALUATOR_VERSION = "EFATA-SCHEMA-EVALUATOR-1"


def _strip_internal_ids(value: Any, *, logical: bool) -> Any:
    if isinstance(value, tuple):
        return tuple(_strip_internal_ids(v, logical=logical) for v in value)
    if isinstance(value, list):
        return [_strip_internal_ids(v, logical=logical) for v in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key == "oid" or key.endswith("_oid"):
                continue
            if key in {"owner_name"}:
                continue  # authorization belongs to SecurityManifest
            if logical and key in {
                "indisready",
                "indislive",
                "access_method",
            }:
                continue
            out[key] = _strip_internal_ids(item, logical=logical)
        return out
    return value


def structural_manifest_sha256(manifest: StructuralManifest) -> str:
    return sha256_canonical(_strip_internal_ids(
        manifest.model_dump(mode="python"),
        logical=False,
    ))


def logical_schema_sha256(manifest: StructuralManifest) -> str:
    return sha256_canonical(_strip_internal_ids(
        manifest.model_dump(mode="python"),
        logical=True,
    ))


def physical_schema_sha256(manifest: StructuralManifest) -> str:
    return structural_manifest_sha256(manifest)


def security_manifest_sha256(manifest: SecurityManifest) -> str:
    return sha256_canonical(manifest)


def logical_security_sha256(manifest: SecurityManifest) -> str:
    return sha256_canonical(manifest)


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch(value, pattern) for pattern in patterns)


def evaluate_schema(
    manifest: StructuralManifest,
    profile: SchemaCompatibilityProfile,
    completeness: CaptureCompletenessReport,
) -> CompatibilityResult:
    profile_sha = sha256_canonical(profile)
    manifest_sha = structural_manifest_sha256(manifest)
    observed = observed_structural_object_ids(manifest)
    required = set(profile.required_objects)
    forbidden = set(profile.forbidden_objects)
    allow_exact = set(profile.required_objects) | set(profile.allowed_extra_objects)

    deltas: list[Delta] = []
    reasons: list[str] = []

    if completeness.status.value != "COMPLETE":
        decision = Decision.INCONCLUSIVE
        reasons.extend(completeness.reason_codes or ("CAPTURE.INCOMPLETE",))
    else:
        for item in sorted(required - observed):
            deltas.append(Delta(
                code="SCHEMA.REQUIRED_OBJECT_MISSING",
                object_id=item,
                expected=True,
                observed=False,
            ))
        for item in sorted(observed & forbidden):
            deltas.append(Delta(
                code="SCHEMA.FORBIDDEN_OBJECT_PRESENT",
                object_id=item,
                expected=False,
                observed=True,
            ))

        # Unknown application-owned objects are deny-by-default. Namespace entries
        # themselves are evaluated through required_namespaces.
        for item in sorted(observed - allow_exact):
            if item.startswith("namespace:"):
                continue
            if item in profile.allowed_recommended_indexes:
                continue
            if _matches_any(item, profile.allowed_extra_patterns):
                continue
            deltas.append(Delta(
                code="SCHEMA.EXTRA_APPLICATION_OBJECT_FORBIDDEN",
                object_id=item,
                expected="allowlisted or absent",
                observed="present",
            ))

        required_namespaces = {f"namespace:{x}" for x in profile.required_namespaces}
        for item in sorted(required_namespaces - observed):
            deltas.append(Delta(
                code="SCHEMA.REQUIRED_NAMESPACE_MISSING",
                object_id=item,
            ))

        if any(d.severity == "ERROR" for d in deltas):
            decision = Decision.INCOMPATIBLE
        elif deltas:
            decision = Decision.COMPATIBLE
        else:
            exact_set = required | set(profile.allowed_extra_objects)
            relevant_observed = {
                x for x in observed
                if not x.startswith("namespace:")
            }
            decision = (
                Decision.EXACT
                if relevant_observed <= exact_set
                else Decision.COMPATIBLE
            )

    reasons.extend(d.code for d in deltas)
    signature_input = {
        "manifest_sha256": manifest_sha,
        "profile_id": profile.profile_id,
        "profile_version": profile.profile_version,
        "profile_sha256": profile_sha,
        "fingerprint_spec_version": manifest.manifest_spec_version,
        "evaluator_version": EVALUATOR_VERSION,
        "decision": decision.value,
        "reason_codes": sorted(set(reasons)),
        "deltas": [d.model_dump(mode="python") for d in deltas],
    }
    return CompatibilityResult(
        decision=decision,
        reason_codes=tuple(sorted(set(reasons))),
        deltas=tuple(deltas),
        profile_sha256=profile_sha,
        compatibility_signature_sha256=sha256_canonical(signature_input),
    )


def evaluate_security(
    manifest: SecurityManifest,
    profile: DatabaseSecurityCompatibilityProfile,
    completeness: CaptureCompletenessReport,
) -> CompatibilityResult:
    profile_sha = sha256_canonical(profile)
    manifest_sha = security_manifest_sha256(manifest)
    observed_facts = observed_security_fact_ids(manifest)
    deltas: list[Delta] = []
    reasons: list[str] = []

    if completeness.status.value != "COMPLETE":
        decision = Decision.INCONCLUSIVE
        reasons.extend(completeness.reason_codes or ("CAPTURE.INCOMPLETE",))
    else:
        for fact in sorted(set(profile.required_security_facts) - observed_facts):
            deltas.append(Delta(
                code="SECURITY.REQUIRED_FACT_MISSING",
                object_id=fact,
                expected=True,
                observed=False,
            ))
        for fact in sorted(set(profile.forbidden_security_facts) & observed_facts):
            deltas.append(Delta(
                code="SECURITY.FORBIDDEN_FACT_PRESENT",
                object_id=fact,
                expected=False,
                observed=True,
            ))

        role_map = {str(r["rolname"]): r for r in manifest.roles}

        # Security-relevant principals must be deterministically classified.
        relevant_roles: set[str] = set()
        for name, row in role_map.items():
            if any(bool(row.get(attr)) for attr in (
                "rolcanlogin", "rolsuper", "rolcreaterole", "rolcreatedb",
                "rolreplication", "rolbypassrls",
            )):
                relevant_roles.add(name)
        for edge in manifest.memberships:
            for key in ("member_role", "granted_role", "grantor_role"):
                if edge.get(key):
                    relevant_roles.add(str(edge[key]))
        for row in (
            list(manifest.database_acl)
            + list(manifest.schema_acls)
            + list(manifest.relation_acls)
            + list(manifest.sequence_acls)
            + list(manifest.function_acls)
            + list(manifest.default_acls)
        ):
            for key in ("owner_name", "grantee"):
                value = row.get(key)
                if value and value != "PUBLIC":
                    relevant_roles.add(str(value))
        for row in manifest.security_definer_functions:
            if row.get("owner_name"):
                relevant_roles.add(str(row["owner_name"]))

        role_to_classes: dict[str, list[str]] = {}
        for rule in profile.principal_rules:
            for role_name in rule.physical_role_names:
                role_to_classes.setdefault(role_name, []).append(rule.principal_class)

        unclassified = sorted(
            role for role in relevant_roles
            if role in role_map
            and not role.startswith("pg_")
            and len(role_to_classes.get(role, [])) == 0
        )
        ambiguous = sorted(
            role for role in relevant_roles
            if len(role_to_classes.get(role, [])) > 1
        )
        if unclassified:
            reasons.append("CAPTURE.PRINCIPAL_UNCLASSIFIED")
            for role in unclassified:
                deltas.append(Delta(
                    code="CAPTURE.PRINCIPAL_UNCLASSIFIED",
                    object_id=f"role:{role}",
                    expected="exactly one principal class",
                    observed="zero mappings",
                    severity="WARNING",
                ))
        if ambiguous:
            reasons.append("CAPTURE.PRINCIPAL_MAPPING_AMBIGUOUS")
            for role in ambiguous:
                deltas.append(Delta(
                    code="CAPTURE.PRINCIPAL_MAPPING_AMBIGUOUS",
                    object_id=f"role:{role}",
                    expected="exactly one principal class",
                    observed=role_to_classes.get(role),
                    severity="WARNING",
                ))

        for rule in profile.principal_rules:
            matches = [name for name in rule.physical_role_names if name in role_map]
            if not (rule.min_count <= len(matches) <= rule.max_count):
                deltas.append(Delta(
                    code="SECURITY.PRINCIPAL_CARDINALITY_MISMATCH",
                    object_id=rule.principal_class,
                    expected=f"{rule.min_count}..{rule.max_count}",
                    observed=len(matches),
                ))
            for role_name in matches:
                row = role_map[role_name]
                for attr in tuple(profile.forbidden_role_attributes) + tuple(rule.forbidden_true_attributes):
                    if bool(row.get(attr)):
                        deltas.append(Delta(
                            code=f"SECURITY.ROLE_ATTRIBUTE_FORBIDDEN.{attr.upper()}",
                            object_id=f"role:{role_name}",
                            expected=False,
                            observed=True,
                        ))
                for attr in rule.required_true_attributes:
                    if not bool(row.get(attr)):
                        deltas.append(Delta(
                            code=f"SECURITY.ROLE_ATTRIBUTE_REQUIRED.{attr.upper()}",
                            object_id=f"role:{role_name}",
                            expected=True,
                            observed=False,
                        ))

        for row in (
            list(manifest.database_acl)
            + list(manifest.schema_acls)
            + list(manifest.relation_acls)
            + list(manifest.sequence_acls)
            + list(manifest.function_acls)
        ):
            if row.get("grantee") == "PUBLIC" and row.get("privilege_type") in profile.forbidden_public_privileges:
                deltas.append(Delta(
                    code="SECURITY.PUBLIC_GRANT_FORBIDDEN",
                    object_id=str(row),
                ))

        hard_errors = [d for d in deltas if d.severity == "ERROR"]
        if hard_errors:
            decision = Decision.INCOMPATIBLE
        elif unclassified or ambiguous:
            decision = Decision.INCONCLUSIVE
        else:
            decision = Decision.EXACT

    reasons.extend(d.code for d in deltas)
    signature_input = {
        "manifest_sha256": manifest_sha,
        "profile_id": profile.profile_id,
        "profile_version": profile.profile_version,
        "profile_sha256": profile_sha,
        "evaluator_version": EVALUATOR_VERSION,
        "decision": decision.value,
        "reason_codes": sorted(set(reasons)),
        "deltas": [d.model_dump(mode="python") for d in deltas],
    }
    return CompatibilityResult(
        decision=decision,
        reason_codes=tuple(sorted(set(reasons))),
        deltas=tuple(deltas),
        profile_sha256=profile_sha,
        compatibility_signature_sha256=sha256_canonical(signature_input),
    )


def derive_overall_decision(
    structural: StructuralManifest,
    security: SecurityManifest,
    schema_profile: SchemaCompatibilityProfile,
    security_profile: DatabaseSecurityCompatibilityProfile,
    completeness: CaptureCompletenessReport,
    *,
    session_profile_sha256: str,
) -> DatabaseCompatibilityDecision:
    schema_result = evaluate_schema(structural, schema_profile, completeness)
    security_result = evaluate_security(security, security_profile, completeness)

    if completeness.status.value != "COMPLETE":
        overall = Decision.INCONCLUSIVE
    elif Decision.INCONCLUSIVE in {schema_result.decision, security_result.decision}:
        overall = Decision.INCONCLUSIVE
    elif Decision.INCOMPATIBLE in {schema_result.decision, security_result.decision}:
        overall = Decision.INCOMPATIBLE
    elif schema_result.decision == Decision.EXACT and security_result.decision == Decision.EXACT:
        overall = Decision.EXACT
    else:
        overall = Decision.COMPATIBLE

    return DatabaseCompatibilityDecision(
        schema_decision=schema_result.decision,
        security_decision=security_result.decision,
        overall_decision=overall,
        structural_manifest_sha256=structural_manifest_sha256(structural),
        security_manifest_sha256=security_manifest_sha256(security),
        logical_schema_sha256=logical_schema_sha256(structural),
        physical_schema_sha256=physical_schema_sha256(structural),
        logical_security_sha256=logical_security_sha256(security),
        schema_profile_sha256=sha256_canonical(schema_profile),
        security_profile_sha256=sha256_canonical(security_profile),
        query_pack_sha256=QUERY_PACK_SHA256,
        session_profile_sha256=session_profile_sha256,
        reason_codes=tuple(sorted(set(
            schema_result.reason_codes + security_result.reason_codes
        ))),
        evaluator_version=EVALUATOR_VERSION,
    )
