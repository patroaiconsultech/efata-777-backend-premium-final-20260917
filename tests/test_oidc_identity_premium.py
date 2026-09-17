from orkio_v2.services.oidc_identity import (
    OIDCIdentityMappingError,
    normalize_oidc_identity,
    safe_oidc_diagnostics,
)
import pytest


TENANT = "org-1"
ROLES_CLAIM = "urn:zitadel:iam:org:project:roles"


def base_payload():
    return {
        "active": True,
        "sub": "user-1",
        "aud": ["385220733510354436"],
        "urn:zitadel:iam:user:resourceowner:id": TENANT,
    }


def test_zitadel_mapping_accepts_only_roles_bound_to_current_tenant():
    payload = base_payload()
    payload[ROLES_CLAIM] = {
        "admin": {TENANT: "patroai.example"},
        "owner": {"other-org": "other.example"},
    }
    identity = normalize_oidc_identity(
        payload,
        user_claim="sub",
        tenant_claim="urn:zitadel:iam:user:resourceowner:id",
        roles_claim=ROLES_CLAIM,
    )
    assert identity.user_id == "user-1"
    assert identity.tenant_id == TENANT
    assert identity.roles == ("admin",)


def test_cross_tenant_admin_is_not_granted():
    payload = base_payload()
    payload[ROLES_CLAIM] = {"admin": {"other-org": "other.example"}}
    identity = normalize_oidc_identity(
        payload,
        user_claim="sub",
        tenant_claim="urn:zitadel:iam:user:resourceowner:id",
        roles_claim=ROLES_CLAIM,
    )
    assert identity.roles == ()


def test_missing_tenant_fails_closed():
    payload = base_payload()
    payload.pop("urn:zitadel:iam:user:resourceowner:id")
    with pytest.raises(OIDCIdentityMappingError) as raised:
        normalize_oidc_identity(
            payload,
            user_claim="sub",
            tenant_claim="urn:zitadel:iam:user:resourceowner:id",
            roles_claim=ROLES_CLAIM,
        )
    assert raised.value.code == "TENANT_CLAIM_MISSING"


def test_invalid_role_shape_fails_closed():
    payload = base_payload()
    payload[ROLES_CLAIM] = 123
    with pytest.raises(OIDCIdentityMappingError) as raised:
        normalize_oidc_identity(
            payload,
            user_claim="sub",
            tenant_claim="urn:zitadel:iam:user:resourceowner:id",
            roles_claim=ROLES_CLAIM,
        )
    assert raised.value.code == "ROLE_CLAIM_INVALID"


def test_safe_diagnostics_never_contains_claim_values():
    payload = base_payload()
    payload[ROLES_CLAIM] = {"admin": {TENANT: "patroai.example"}}
    result = safe_oidc_diagnostics(
        payload,
        user_claim="sub",
        tenant_claim="urn:zitadel:iam:user:resourceowner:id",
        roles_claim=ROLES_CLAIM,
    )
    serialized = repr(result)
    assert "user-1" not in serialized
    assert TENANT not in serialized
    assert "patroai.example" not in serialized
    assert result["roles_claim_type"] == "mapping"



def test_zitadel_claim_defaults_match_runtime_contract():
    from orkio_v2.config import Settings

    settings = Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
    )
    assert settings.oidc_user_claim == "sub"
    assert settings.oidc_tenant_claim == "urn:zitadel:iam:user:resourceowner:id"
    assert settings.oidc_roles_claim == "urn:zitadel:iam:org:project:roles"
