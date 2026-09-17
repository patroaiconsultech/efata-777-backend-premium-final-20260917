from __future__ import annotations

from fnmatch import fnmatch
from typing import Iterable

from .canonical import sha256_canonical

from .contracts import (
    CaptureCompletenessReport,
    CompletenessStatus,
    SecurityManifest,
    StructuralManifest,
)
from .query_pack import REQUIRED_CATALOG_SURFACES


class GroundTruthContractError(RuntimeError):
    pass


def validate_ground_truth_contract(ground_truth: dict) -> None:
    if ground_truth.get("authorship_mode") != "INDEPENDENT_STATIC_CONTRACT":
        raise GroundTruthContractError("CAPTURE.GROUND_TRUTH_NOT_INDEPENDENT")
    if ground_truth.get("review_status") != "APPROVED":
        raise GroundTruthContractError("CAPTURE.GROUND_TRUTH_NOT_APPROVED")
    declared = ground_truth.get("ground_truth_sha256")
    material = {k: v for k, v in ground_truth.items() if k != "ground_truth_sha256"}
    if not declared or declared != sha256_canonical(material):
        raise GroundTruthContractError("CAPTURE.GROUND_TRUTH_HASH_MISMATCH")


RELKIND_PREFIX = {
    "r": "table",
    "p": "table",
    "v": "view",
    "m": "materialized_view",
    "S": "sequence",
    "f": "foreign_table",
}


def observed_structural_object_ids(manifest: StructuralManifest) -> set[str]:
    out: set[str] = set()
    for row in manifest.namespaces:
        out.add(f'namespace:{row["schema_name"]}')
    for row in manifest.relations:
        prefix = RELKIND_PREFIX.get(str(row.get("relkind")), "relation")
        out.add(f'{prefix}:{row["schema_name"]}.{row["object_name"]}')
    for row in manifest.columns:
        out.add(
            f'column:{row["schema_name"]}.{row["relation_name"]}.{row["column_name"]}'
        )
    for row in manifest.constraints:
        out.add(
            f'constraint:{row["schema_name"]}.{row["relation_name"]}.{row["constraint_name"]}'
        )
    for row in manifest.indexes:
        out.add(
            f'index:{row["schema_name"]}.{row["relation_name"]}.{row["index_name"]}'
        )
    for row in manifest.types:
        out.add(f'type:{row["schema_name"]}.{row["type_name"]}')
    for row in manifest.sequences:
        out.add(f'sequence:{row["schema_name"]}.{row["sequence_name"]}')
    for row in manifest.functions:
        out.add(
            f'function:{row["schema_name"]}.{row["function_name"]}({row.get("identity_arguments") or ""})'
        )
    for row in manifest.views:
        out.add(f'view:{row["schema_name"]}.{row["view_name"]}')
    for row in manifest.triggers:
        out.add(
            f'trigger:{row["schema_name"]}.{row["relation_name"]}.{row["trigger_name"]}'
        )
    for row in manifest.rls_policies:
        out.add(
            f'rls_policy:{row["schema_name"]}.{row["relation_name"]}.{row["policy_name"]}'
        )
    return out


def observed_security_fact_ids(manifest: SecurityManifest) -> set[str]:
    out: set[str] = set()
    for role in manifest.roles:
        name = role["rolname"]
        out.add(f"role:{name}")
        for attr in (
            "rolcanlogin",
            "rolsuper",
            "rolinherit",
            "rolcreaterole",
            "rolcreatedb",
            "rolreplication",
            "rolbypassrls",
        ):
            out.add(f"role_attr:{name}:{attr}={str(bool(role.get(attr))).lower()}")
    for edge in manifest.memberships:
        out.add(
            "membership:"
            f'{edge["member_role"]}->{edge["granted_role"]}:'
            f'inherit={str(bool(edge.get("inherit_option"))).lower()}:'
            f'set={str(bool(edge.get("set_option"))).lower()}:'
            f'admin={str(bool(edge.get("admin_option"))).lower()}'
        )
    for row in manifest.database_acl:
        out.add(
            f'db_acl:{row["grantee"]}:{row["privilege_type"]}:'
            f'grantable={str(bool(row.get("is_grantable"))).lower()}'
        )
    for attr_name, rows, label_fields in (
        ("schema_acl", manifest.schema_acls, ("schema_name",)),
        ("relation_acl", manifest.relation_acls, ("schema_name", "relation_name")),
        ("sequence_acl", manifest.sequence_acls, ("schema_name", "relation_name")),
        ("function_acl", manifest.function_acls, ("schema_name", "function_name", "identity_arguments")),
    ):
        for row in rows:
            label = ".".join(str(row.get(k) or "") for k in label_fields)
            out.add(
                f'{attr_name}:{label}:{row["grantee"]}:{row["privilege_type"]}:'
                f'grantable={str(bool(row.get("is_grantable"))).lower()}'
            )
    for row in manifest.security_definer_functions:
        out.add(
            f'security_definer:{row["identity"]}:definition_sha256={row["function_definition_sha256"]}'
        )
    return out


def _id_class(value: str) -> str:
    return value.split(":", 1)[0]


def _count_ids_by_declared_class(
    values: Iterable[str],
    declared_counts: dict[str, int],
) -> dict[str, int]:
    counts = {str(name): 0 for name in declared_counts}
    for value in values:
        item_class = _id_class(value)
        if item_class in counts:
            counts[item_class] += 1
    return counts


def _normalize_declared_counts(value: object) -> dict[str, int]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise GroundTruthContractError("CAPTURE.GROUND_TRUTH_CARDINALITY_INVALID")
    normalized: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str) or not key:
            raise GroundTruthContractError("CAPTURE.GROUND_TRUTH_CARDINALITY_INVALID")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise GroundTruthContractError("CAPTURE.GROUND_TRUTH_CARDINALITY_INVALID")
        normalized[key] = count
    return normalized


def build_completeness_report(
    structural: StructuralManifest,
    security: SecurityManifest,
    ground_truth: dict,
    *,
    observed_surfaces: Iterable[str],
    failed_surfaces: Iterable[str] = (),
) -> CaptureCompletenessReport:
    required_surfaces = tuple(sorted(ground_truth.get(
        "required_catalog_surfaces",
        REQUIRED_CATALOG_SURFACES,
    )))
    observed_surfaces_set = set(observed_surfaces)
    failed_surfaces_set = set(failed_surfaces)
    missing_surfaces = sorted(set(required_surfaces) - observed_surfaces_set)

    observed_objects = observed_structural_object_ids(structural)
    expected_objects = set(ground_truth.get("required_objects", ()))
    missing_objects = tuple(sorted(expected_objects - observed_objects))

    expected_security = set(ground_truth.get("required_security_facts", ()))
    observed_security = observed_security_fact_ids(security)
    missing_security = sorted(expected_security - observed_security)

    declared_object_counts = _normalize_declared_counts(
        ground_truth.get("required_object_count_by_class")
    )
    observed_object_counts = _count_ids_by_declared_class(
        observed_objects,
        declared_object_counts,
    )
    expected_object_counts = _count_ids_by_declared_class(
        expected_objects,
        declared_object_counts,
    )
    object_cardinality_mismatch = any(
        expected_object_counts[name] != expected
        or observed_object_counts[name] != expected
        for name, expected in declared_object_counts.items()
    )

    declared_security_counts = _normalize_declared_counts(
        ground_truth.get("required_security_fact_count_by_class")
    )
    observed_security_counts = _count_ids_by_declared_class(
        observed_security,
        declared_security_counts,
    )
    expected_security_counts = _count_ids_by_declared_class(
        expected_security,
        declared_security_counts,
    )
    security_cardinality_mismatch = any(
        expected_security_counts[name] != expected
        or observed_security_counts[name] != expected
        for name, expected in declared_security_counts.items()
    )

    reasons: list[str] = []
    if missing_surfaces or failed_surfaces_set:
        reasons.append("CAPTURE.REQUIRED_OBJECT_CLASS_NOT_OBSERVABLE")
    if missing_objects:
        reasons.append("CAPTURE.GROUND_TRUTH_OBJECT_MISSING")
    if missing_security:
        reasons.append("CAPTURE.GROUND_TRUTH_SECURITY_FACT_MISSING")
    if object_cardinality_mismatch:
        reasons.append("CAPTURE.GROUND_TRUTH_OBJECT_CARDINALITY_MISMATCH")
    if security_cardinality_mismatch:
        reasons.append("CAPTURE.GROUND_TRUTH_SECURITY_CARDINALITY_MISMATCH")

    unclassified_namespaces = tuple(sorted(
        set(ground_truth.get("unclassified_namespaces", ()))
    ))
    unclassified_objects = tuple(sorted(
        set(ground_truth.get("unclassified_objects", ()))
    ))
    unclassified_principals = tuple(sorted(
        set(ground_truth.get("unclassified_principals", ()))
    ))
    if unclassified_namespaces:
        reasons.append("CAPTURE.UNCLASSIFIED_NAMESPACE")
    if unclassified_objects:
        reasons.append("CAPTURE.OBJECT_OWNERSHIP_UNCLASSIFIED")
    if unclassified_principals:
        reasons.append("CAPTURE.PRINCIPAL_UNCLASSIFIED")

    status = (
        CompletenessStatus.COMPLETE
        if not reasons
        else CompletenessStatus.INCOMPLETE
    )
    return CaptureCompletenessReport(
        completeness_proof_mode="LOCAL_FIXTURE_GROUND_TRUTH_V1",
        required_catalog_surfaces=required_surfaces,
        observed_catalog_surfaces=tuple(sorted(observed_surfaces_set)),
        failed_catalog_surfaces=tuple(sorted(failed_surfaces_set | set(missing_surfaces))),
        missing_ground_truth_objects=missing_objects,
        unexpected_ground_truth_objects=(),
        unclassified_namespaces=unclassified_namespaces,
        unclassified_objects=unclassified_objects,
        unclassified_principals=unclassified_principals,
        cross_reference_failures=tuple(sorted(missing_security)),
        status=status,
        reason_codes=tuple(sorted(set(reasons))),
    )
