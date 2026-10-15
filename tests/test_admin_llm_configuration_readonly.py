"""Admin LLM read-only inspection: authorization, accurate scope, no secrets."""
from __future__ import annotations

from orkio_v2.config import get_settings
from conftest import headers

PATH = "/api/v2/admin/agent-studio/llm-configuration"


def _setup(monkeypatch, *, owner: str = "sub-1", allowlist: str = "owner@example.com"):
    monkeypatch.setenv("PLATFORM_OWNER_SUBJECT", owner)
    monkeypatch.setenv("PLATFORM_ADMIN_EMAIL_ALLOWLIST", allowlist)
    monkeypatch.setenv("PLATFORM_LLM_PRIMARY_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_DEFAULT_MODEL", "gpt-6.1-sol")
    monkeypatch.setenv("OPENAI_API_KEY", "NEVER_EXPOSE_THIS_KEY")
    get_settings.cache_clear()


def test_admin_reads_process_default_without_secrets(client, monkeypatch):
    _setup(monkeypatch)
    try:
        response = client.get(PATH, headers=headers())
        assert response.status_code == 200, response.text
        assert response.json() == {
            "primary_provider": "openai",
            "configured_model": "gpt-6.1-sol",
            "configuration_scope": "process",
            "configuration_source": "resolved_settings",
            "execution_model_verified": False,
            "admin_editable": False,
        }
        assert "NEVER_EXPOSE_THIS_KEY" not in response.text
    finally:
        get_settings.cache_clear()


def test_non_admin_cannot_read_or_claim_admin_role_from_client(client, monkeypatch):
    _setup(monkeypatch, owner="unrelated-subject")
    try:
        # Membership-derived authority must prevail over self-declared headers.
        response = client.get(PATH, headers=headers(roles="superadmin,admin"))
        assert response.status_code == 403
        assert response.json()["detail"] == "SUPERADMIN_ROLE_REQUIRED"
    finally:
        get_settings.cache_clear()


def test_allowlist_denial_and_no_anonymous_access(client, monkeypatch):
    _setup(monkeypatch, allowlist="another@example.com")
    try:
        response = client.get(PATH, headers=headers())
        assert response.status_code == 403
        assert response.json()["detail"] == "ADMIN_ALLOWLIST_REQUIRED"
        anon = client.get(PATH)
        assert anon.status_code in {401, 403}
    finally:
        get_settings.cache_clear()


def test_alternate_primary_provider_is_not_mislabeled_as_openai(client, monkeypatch):
    _setup(monkeypatch)
    monkeypatch.setenv("PLATFORM_LLM_PRIMARY_PROVIDER", "google")
    monkeypatch.setenv("GOOGLE_DEFAULT_MODEL", "gemini-test-choice")
    get_settings.cache_clear()
    try:
        response = client.get(PATH, headers=headers())
        assert response.status_code == 200, response.text
        assert response.json()["primary_provider"] == "google"
        assert response.json()["configured_model"] == "gemini-test-choice"
        assert response.json()["execution_model_verified"] is False
    finally:
        get_settings.cache_clear()
