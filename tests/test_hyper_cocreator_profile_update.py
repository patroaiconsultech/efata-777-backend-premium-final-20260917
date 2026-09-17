from types import SimpleNamespace

from orkio_v2.auth import Principal
from orkio_v2.services.hyper_cocreator import update_profile_name


class FakeDB:
    def __init__(self):
        self.profile = None
        self.added = []
        self.commits = 0

    def scalar(self, _stmt):
        return self.profile

    def add(self, obj):
        self.added.append(obj)
        self.profile = obj

    def commit(self):
        self.commits += 1

    def refresh(self, _obj):
        return None


def principal():
    return Principal(
        user_id="u1",
        tenant_id="t1",
        roles=("member",),
        email="user@example.com",
        external_subject="sub1"
    )


def test_update_profile_name_creates_profile():
    db = FakeDB()
    profile = update_profile_name(
        db,
        principal=principal(),
        co_creator_name="Atlas",
    )
    assert profile.co_creator_name == "Atlas"
    assert profile.tenant_id == "t1"
    assert profile.user_id == "u1"
    assert db.commits == 1


def test_update_profile_name_updates_existing_profile():
    db = FakeDB()
    db.profile = SimpleNamespace(
        tenant_id="t1",
        user_id="u1",
        co_creator_name="Nexo",
        onboarding_goal=None,
    )
    profile = update_profile_name(
        db,
        principal=principal(),
        co_creator_name="Sophia",
    )
    assert profile.co_creator_name == "Sophia"
    assert db.commits == 1


def test_access_gate_rejects_incomplete_configuration():
    from types import SimpleNamespace
    from orkio_v2.services.hyper_cocreator import AccessGateError, validate_access_code
    settings = SimpleNamespace(
        access_gate_enabled=True,
        access_gate_signing_secret="",
        access_gate_code_hashes="",
        access_gate_tenant_id="",
        access_gate_ttl_seconds=600,
    )
    try:
        validate_access_code(settings, "example")
    except AccessGateError as exc:
        assert exc.code == "ACCESS_GATE_NOT_CONFIGURED"
    else:
        raise AssertionError("expected ACCESS_GATE_NOT_CONFIGURED")
