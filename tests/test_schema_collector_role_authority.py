from tools.efata_schema_collector.contracts import AccessMode
from tools.efata_schema_collector.role_authority import evaluate_authority


def role(name, **attrs):
    row = {
        "rolname": name,
        "rolsuper": False,
        "rolbypassrls": False,
        "rolcreaterole": False,
        "rolcreatedb": False,
        "rolreplication": False,
    }
    row.update(attrs)
    return row


def edge(member, granted, *, inherit=True, set_=True, admin=False):
    return {
        "member_role": member,
        "granted_role": granted,
        "grantor_role": "bootstrap",
        "inherit_option": inherit,
        "set_option": set_,
        "admin_option": admin,
    }


def test_transitive_set_role_special_authority_preserves_path():
    roles = [
        role("runtime"),
        role("role_a"),
        role("privileged", rolbypassrls=True),
    ]
    memberships = [
        edge("runtime", "role_a", inherit=True, set_=True),
        edge("role_a", "privileged", inherit=False, set_=True),
    ]
    result = evaluate_authority("runtime", roles, memberships)
    proof = next(p for p in result.proofs if p.privilege == "BYPASSRLS")
    assert proof.access_mode == AccessMode.SET_ROLE
    assert [(e.from_role, e.to_role) for e in proof.proof_path] == [
        ("runtime", "role_a"),
        ("role_a", "privileged"),
    ]


def test_set_role_false_blocks_special_authority():
    roles = [
        role("runtime"),
        role("role_a"),
        role("privileged", rolbypassrls=True),
    ]
    memberships = [
        edge("runtime", "role_a", inherit=True, set_=True),
        edge("role_a", "privileged", inherit=False, set_=False),
    ]
    result = evaluate_authority("runtime", roles, memberships)
    assert "BYPASSRLS" not in result.summary


def test_inherit_true_transitively_exposes_ordinary_privilege():
    roles = [role("runtime"), role("a"), role("b")]
    memberships = [
        edge("runtime", "a", inherit=True, set_=False),
        edge("a", "b", inherit=True, set_=False),
    ]
    result = evaluate_authority(
        "runtime",
        roles,
        memberships,
        role_privileges={"b": {"SELECT:public.items"}},
    )
    proof = next(p for p in result.proofs if p.privilege == "SELECT:public.items")
    assert proof.access_mode == AccessMode.INHERITED
    assert len(proof.proof_path) == 2


def test_inherit_false_breaks_inherited_privilege_path():
    roles = [role("runtime"), role("a"), role("b")]
    memberships = [
        edge("runtime", "a", inherit=True, set_=False),
        edge("a", "b", inherit=False, set_=False),
    ]
    result = evaluate_authority(
        "runtime",
        roles,
        memberships,
        role_privileges={"b": {"SELECT:public.items"}},
    )
    assert "SELECT:public.items" not in result.summary


def test_admin_option_is_explicit_proof_not_ordinary_privilege():
    roles = [role("runtime"), role("managed")]
    memberships = [edge("runtime", "managed", inherit=False, set_=False, admin=True)]
    result = evaluate_authority("runtime", roles, memberships)
    proof = next(p for p in result.proofs if p.privilege == "ADMIN_ROLE_MEMBERSHIP:managed")
    assert proof.access_mode == AccessMode.ADMIN_CAPABILITY
    assert len(proof.proof_path) == 1
