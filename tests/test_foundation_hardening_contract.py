from __future__ import annotations

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_release_manifest_generator_is_present_and_secret_free_by_contract():
    text = (ROOT / "scripts" / "build_release_manifest.py").read_text(encoding="utf-8")
    assert "commit_sha" in text
    assert "migration_head" in text
    assert "requirements_lock_sha256" in text
    assert "OPENAI_API_KEY" not in text
    assert "DATABASE_URL" not in text


def test_migration_hygiene_gate_passes_with_revision_001_grandfathered():
    completed = subprocess.run(
        [sys.executable, "scripts/check_migration_hygiene.py"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    assert "MIGRATION_HYGIENE_PASS" in completed.stdout
    assert "EFATA-AUD-001" in completed.stdout


def test_realtime_voice_preflight_uses_sanitized_provider_configuration_state():
    text = (ROOT / "scripts" / "check_realtime_voice.py").read_text(encoding="utf-8")
    assert "provider_configuration_state" in text
    assert "openai_api_key_configured" not in text
    assert '"secrets"' not in text
    assert "settings.openai_api_key" in text
    assert "print(settings.openai_api_key)" not in text

def test_postgres_workflow_uses_immutable_action_shas():
    text = (ROOT / ".github" / "workflows" / "03-postgres-integration.yml").read_text(
        encoding="utf-8"
    )
    assert "actions/checkout@v4" not in text
    assert "actions/setup-python@v5" not in text
    assert "actions/upload-artifact@v4" not in text
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in text
    assert "actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38" in text
    assert "actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882" in text

def test_all_backend_workflows_use_immutable_external_action_shas():
    import re

    workflows = ROOT / ".github" / "workflows"
    uses_re = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
    sha_re = re.compile(r"^[0-9a-fA-F]{40}$")

    violations = []
    for path in sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        for ref in uses_re.findall(text):
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            if "@" not in ref:
                violations.append((path.name, ref))
                continue
            _, pinned_ref = ref.rsplit("@", 1)
            if not sha_re.fullmatch(pinned_ref):
                violations.append((path.name, ref))

    assert violations == []


def test_core_backend_ci_runs_workflow_pinning_gate():
    text = (ROOT / ".github" / "workflows" / "01-backend-ci.yml").read_text(
        encoding="utf-8"
    )
    assert "python scripts/check_workflow_action_pinning.py" in text

