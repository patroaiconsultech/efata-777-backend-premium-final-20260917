from orkio_v2.config import Settings


def test_settings_exposes_platform_owner_subject_contract(monkeypatch):
    monkeypatch.delenv("PLATFORM_OWNER_SUBJECT", raising=False)
    settings = Settings()
    assert hasattr(settings, "platform_owner_subject")
    assert settings.platform_owner_subject is None


def test_settings_reads_platform_owner_subject_from_env(monkeypatch):
    monkeypatch.setenv("PLATFORM_OWNER_SUBJECT", "founder-subject-test")
    settings = Settings()
    assert settings.platform_owner_subject == "founder-subject-test"
