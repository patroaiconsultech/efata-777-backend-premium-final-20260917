from __future__ import annotations

from collections import deque
from typing import Iterable

from .contracts import (
    AccessMode,
    AuthorityEvaluation,
    AuthorityProof,
    RoleMembershipProofEdge,
)


class RoleGraphError(RuntimeError):
    pass


SPECIAL_ROLE_ATTRIBUTES = {
    "rolsuper": "SUPERUSER",
    "rolbypassrls": "BYPASSRLS",
    "rolcreaterole": "CREATEROLE",
    "rolcreatedb": "CREATEDB",
    "rolreplication": "REPLICATION",
}


def _edge_from_row(row: dict) -> RoleMembershipProofEdge:
    return RoleMembershipProofEdge(
        from_role=str(row["member_role"]),
        to_role=str(row["granted_role"]),
        inherit_option=bool(row.get("inherit_option")),
        set_option=bool(row.get("set_option")),
        admin_option=bool(row.get("admin_option")),
        grantor=(str(row["grantor_role"]) if row.get("grantor_role") else None),
    )


def _adjacency(memberships: Iterable[dict]) -> dict[str, list[RoleMembershipProofEdge]]:
    graph: dict[str, list[RoleMembershipProofEdge]] = {}
    for row in memberships:
        edge = _edge_from_row(row)
        graph.setdefault(edge.from_role, []).append(edge)
    for edges in graph.values():
        edges.sort(key=lambda e: (e.to_role, e.grantor or ""))
    return graph


def _paths(
    start: str,
    graph: dict[str, list[RoleMembershipProofEdge]],
    *,
    option: str,
) -> dict[str, tuple[RoleMembershipProofEdge, ...]]:
    if option not in {"inherit_option", "set_option"}:
        raise ValueError(option)
    found: dict[str, tuple[RoleMembershipProofEdge, ...]] = {start: ()}
    queue = deque([start])
    while queue:
        current = queue.popleft()
        for edge in graph.get(current, []):
            if not getattr(edge, option):
                continue
            # PostgreSQL rejects cycles; fail closed if fixture/input violates that invariant.
            path_roles = {start}
            for prior in found[current]:
                path_roles.add(prior.to_role)
            if edge.to_role in path_roles:
                raise RoleGraphError("CAPTURE.ROLE_GRAPH_CYCLE")
            if edge.to_role not in found:
                found[edge.to_role] = found[current] + (edge,)
                queue.append(edge.to_role)
    return found


def inherited_closure(
    role: str,
    memberships: Iterable[dict],
) -> dict[str, tuple[RoleMembershipProofEdge, ...]]:
    return _paths(role, _adjacency(memberships), option="inherit_option")


def set_role_closure(
    role: str,
    memberships: Iterable[dict],
) -> dict[str, tuple[RoleMembershipProofEdge, ...]]:
    return _paths(role, _adjacency(memberships), option="set_option")


def evaluate_authority(
    principal: str,
    roles: Iterable[dict],
    memberships: Iterable[dict],
    role_privileges: dict[str, set[str]] | None = None,
) -> AuthorityEvaluation:
    role_map = {str(row["rolname"]): dict(row) for row in roles}
    membership_rows = [dict(row) for row in memberships]
    graph = _adjacency(membership_rows)
    if principal not in role_map:
        raise RoleGraphError(f"CAPTURE.PRINCIPAL_UNCLASSIFIED:{principal}")

    role_privileges = role_privileges or {}
    set_paths = _paths(principal, graph, option="set_option")
    proofs: list[AuthorityProof] = []

    def add_proof(
        privilege: str,
        access_mode: AccessMode,
        effective_state: str,
        path: tuple[RoleMembershipProofEdge, ...],
        source_object: str | None = None,
    ) -> None:
        proof = AuthorityProof(
            principal=principal,
            privilege=privilege,
            access_mode=access_mode,
            initial_role=principal,
            effective_role_state=effective_state,
            proof_path=path,
            source_object=source_object,
        )
        if proof not in proofs:
            proofs.append(proof)

    # Every SET-reachable role is an actual role state the session can assume.
    for state_role, set_path in sorted(set_paths.items()):
        state = role_map.get(state_role)
        if state is None:
            raise RoleGraphError(f"CAPTURE.PRINCIPAL_UNCLASSIFIED:{state_role}")

        # Special role attributes are usable only in that actual role state,
        # never merely because the state is inherited.
        for field, privilege in SPECIAL_ROLE_ATTRIBUTES.items():
            if bool(state.get(field)):
                add_proof(
                    privilege,
                    AccessMode.DIRECT if state_role == principal else AccessMode.SET_ROLE,
                    state_role,
                    set_path,
                )

        # Ordinary object privileges of the active role plus inherited roles.
        inherit_paths = _paths(state_role, graph, option="inherit_option")
        for privilege in sorted(role_privileges.get(state_role, set())):
            add_proof(
                privilege,
                AccessMode.DIRECT if state_role == principal else AccessMode.SET_ROLE,
                state_role,
                set_path,
            )
        for inherited_role, inherit_path in sorted(inherit_paths.items()):
            if inherited_role == state_role:
                continue
            for privilege in sorted(role_privileges.get(inherited_role, set())):
                combined = set_path + inherit_path
                add_proof(
                    privilege,
                    AccessMode.INHERITED if state_role == principal else AccessMode.SET_ROLE,
                    state_role,
                    combined,
                    source_object=inherited_role,
                )

        # ADMIN OPTION is a membership-management capability of the active role.
        for edge in graph.get(state_role, []):
            if edge.admin_option:
                add_proof(
                    f"ADMIN_ROLE_MEMBERSHIP:{edge.to_role}",
                    AccessMode.ADMIN_CAPABILITY,
                    state_role,
                    set_path + (edge,),
                )

    proofs.sort(
        key=lambda p: (
            p.privilege,
            p.access_mode.value,
            p.effective_role_state,
            tuple((e.from_role, e.to_role) for e in p.proof_path),
        )
    )
    return AuthorityEvaluation(
        principal=principal,
        summary=tuple(sorted({p.privilege for p in proofs})),
        proofs=tuple(proofs),
    )
