from __future__ import annotations
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import types
import pytest
from packaging.tags import Tag

HERE = Path(__file__).resolve().parents[1]


def load(relative):
    spec = importlib.util.spec_from_file_location("module_under_test", HERE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wheelmod = load("scripts/p0_validate_wheelhouse.py")
ocimod = load("scripts/p0_verify_oci_manifest.py")


def setup_wheel(tmp_path, monkeypatch, name="sample-1.0-py3-none-any.whl", content=b"mock wheel, not executable"):
    lock = tmp_path / "requirements-test.lock.txt"
    folder = tmp_path / "wheels"
    folder.mkdir()
    whl = folder / name
    whl.write_bytes(content)
    lock.write_text(f"sample==1.0 \\\n    --hash=sha256:{sha256(content).hexdigest()}\n", encoding="utf8")
    monkeypatch.setattr(wheelmod, "sys", types.SimpleNamespace(version_info=(3, 12, 9)))
    monkeypatch.setattr(wheelmod, "sys_tags", lambda: iter([
        Tag("py3", "none", "any"), Tag("cp312", "cp312", "manylinux_2_17_x86_64")
    ]))
    return lock, folder, whl


def test_wheel_valid_tag_hash(tmp_path, monkeypatch):
    lock, folder, _ = setup_wheel(tmp_path, monkeypatch)
    result = wheelmod.validate(lock, folder, sha256(lock.read_bytes()).hexdigest())
    assert len(result["wheels"]) == 1 and result["installed_or_resolved_offline"] is False


def test_hash_rejected(tmp_path, monkeypatch):
    lock, folder, whl = setup_wheel(tmp_path, monkeypatch)
    whl.write_bytes(b"changed")
    with pytest.raises(ValueError, match="WHEEL_HASH_NOT_IN_LOCK"):
        wheelmod.validate(lock, folder, sha256(lock.read_bytes()).hexdigest())


def test_incompatible_tag_rejected(tmp_path, monkeypatch):
    lock, folder, whl = setup_wheel(tmp_path, monkeypatch)
    content = whl.read_bytes()
    whl.unlink()
    new = folder / "sample-1.0-cp311-cp311-win_amd64.whl"
    new.write_bytes(content)
    with pytest.raises(ValueError, match="INCOMPATIBLE_TAGS"):
        wheelmod.validate(lock, folder, sha256(lock.read_bytes()).hexdigest())


def test_unknown_file_rejected(tmp_path, monkeypatch):
    lock, folder, _ = setup_wheel(tmp_path, monkeypatch)
    (folder / "evil.tar.gz").write_text("not a wheel")
    with pytest.raises(ValueError, match="UNEXPECTED_FILE"):
        wheelmod.validate(lock, folder, sha256(lock.read_bytes()).hexdigest())


def test_wrong_expected_lock_rejected(tmp_path, monkeypatch):
    lock, folder, _ = setup_wheel(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="LOCK_SHA256_MISMATCH"):
        wheelmod.validate(lock, folder, "0" * 64)


def test_non_pinned_lock_rejected(tmp_path):
    lock = tmp_path / "requirements.txt"
    lock.write_text("sample>=1.0\n")
    with pytest.raises(ValueError, match="EMPTY_OR_NONPINNED_LOCK"):
        wheelmod.read_lock(lock)


def test_image_manifest_platform_valid():
    payload = json.dumps({"schemaVersion": 2, "manifests": [
        {"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "amd64"}}
    ]}).encode()
    result = ocimod.inspect_manifest(payload, "docker.io/library/postgres:18.6")
    assert result["docker_image_run"] is False


def test_image_manifest_missing_platform():
    payload = json.dumps({"manifests": [
        {"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "arm64"}}
    ]}).encode()
    with pytest.raises(ValueError, match="NO_LINUX_AMD64_PLATFORM"):
        ocimod.inspect_manifest(payload, "docker.io/library/postgres:18.6")


def test_image_manifest_ref_allowlist():
    with pytest.raises(ValueError, match="IMAGE_TAG_NOT_ALLOWLISTED"):
        ocimod.inspect_manifest(b"{}", "evil.registry.com/evil:latest")


def test_workflow_manual_only_without_db_or_migration():
    import yaml
    raw = (HERE / ".github/workflows/05-p0-provenance-prep.yml").read_text()
    doc = yaml.load(raw, Loader=yaml.BaseLoader)
    assert list(doc["on"]) == ["workflow_dispatch"]
    assert doc["permissions"] == {"contents": "read"}
    assert "pull_request:" not in raw
    assert "push:" not in raw
    assert "alembic upgrade" not in raw
    assert "docker run" not in raw.replace("sem docker run/pull", "")
    assert "DATABASE_URL" not in raw
    assert "railway login" not in raw
    assert "03-postgres-integration.yml" in raw
    assert doc["jobs"]["p0-provenance-only"]["steps"][-1]["if"] == "always()"


def test_existing_pg16_byte_identical():
    original = HERE / "reference/03-postgres-integration.original.yml"
    assert sha256(original.read_bytes()).hexdigest() == "cb9ffb14902b59734229be580447517e702144e7720d53293bb5df048a19ad55"


def test_b39_lock_sha():
    lock = HERE / "reference/requirements-test.B39.lock.txt"
    assert sha256(lock.read_bytes()).hexdigest() == "bd12488043a326e96c86b03abf888eebf6fc43252760d2c2fdb29d20fc3bc226"


def test_wheelhouse_missing_package_rejected(tmp_path, monkeypatch):
    lock, folder, _ = setup_wheel(tmp_path, monkeypatch)
    lock.write_text(
        lock.read_text() +
        "second==2.0 \\\n    --hash=sha256:" + "a" * 64 + "\n",
        encoding="utf8",
    )
    with pytest.raises(ValueError, match="MISSING_WHEELS_FOR_LOCK:second"):
        wheelmod.validate(lock, folder, sha256(lock.read_bytes()).hexdigest())


def test_wheelhouse_complete_exact_set(tmp_path, monkeypatch):
    lock, folder, _ = setup_wheel(tmp_path, monkeypatch)
    extra = folder / "second-2.0-py3-none-any.whl"
    extra.write_bytes(b"second mocked wheel")
    lock.write_text(
        lock.read_text() +
        "second==2.0 \\\n    --hash=sha256:" + sha256(extra.read_bytes()).hexdigest() + "\n",
        encoding="utf8",
    )
    result = wheelmod.validate(lock, folder, sha256(lock.read_bytes()).hexdigest())
    assert result["complete_against_applicable_lock"] is True
    assert result["applicable_package_count"] == 2
    assert result["wheel_count"] == 2
    assert {w["name"] for w in result["wheels"]} == {"sample", "second"}


def test_inactive_windows_marker_excluded_from_completeness(tmp_path, monkeypatch):
    lock, folder, _ = setup_wheel(tmp_path, monkeypatch)
    lock.write_text(
        lock.read_text() +
        "winpkg==2.0 ; sys_platform == 'win32' \\\n    --hash=sha256:" + "a" * 64 + "\n",
        encoding="utf8",
    )
    result = wheelmod.validate(lock, folder, sha256(lock.read_bytes()).hexdigest())
    assert result["applicable_package_count"] == 1
    assert result["excluded_by_marker"] == ["winpkg"]


def test_inactive_windows_marker_wheel_rejected(tmp_path, monkeypatch):
    lock, folder, _ = setup_wheel(tmp_path, monkeypatch)
    lock.write_text(
        lock.read_text() +
        "winpkg==2.0 ; sys_platform == 'win32' \\\n    --hash=sha256:" + "a" * 64 + "\n",
        encoding="utf8",
    )
    (folder / "winpkg-2.0-py3-none-any.whl").write_bytes(b"random")
    with pytest.raises(ValueError, match="UNDECLARED_OR_INACTIVE_WHEEL"):
        wheelmod.validate(lock, folder, sha256(lock.read_bytes()).hexdigest())


def test_actual_b39_marker_coverage_count():
    locked = wheelmod.read_lock(HERE / "reference/requirements-test.B39.lock.txt")
    assert len(locked) == 71
    env = wheelmod.default_environment()
    env.update({
        "python_version": "3.12",
        "python_full_version": "3.12.9",
        "sys_platform": "linux",
        "os_name": "posix",
        "platform_machine": "x86_64",
        "implementation_name": "cpython",
        "platform_python_implementation": "CPython",
    })
    active = {n for n, (_, _, marker) in locked.items()
              if not marker or wheelmod.Marker(marker).evaluate(environment=env)}
    assert len(active) == 69
    assert set(locked) - active == {"colorama", "tzdata"}


def test_workflow_sha_gate_fail_closed():
    import yaml
    raw = (HERE / ".github/workflows/05-p0-provenance-prep.yml").read_text()
    doc = yaml.load(raw, Loader=yaml.BaseLoader)
    assert doc["on"]["workflow_dispatch"]["inputs"]["approved_sha"]["required"] == "true"
    assert "vars.EFATA_P0_GHA05_APPROVED_SHA" in raw
    assert "[[ \"${P0_AO01_APPROVED_SHA}\" =~ ^[0-9a-f]{40}$ ]]" in raw
    assert 'test "${P0_OPERATOR_SHA}" = "${P0_AO01_APPROVED_SHA}"' in raw
    assert 'test "${GITHUB_SHA}" = "${P0_AO01_APPROVED_SHA}"' in raw
    assert 'test "${actual}" = "${P0_AO01_APPROVED_SHA}"' in raw
    assert doc["permissions"] == {"contents": "read"}
    assert list(doc["on"]) == ["workflow_dispatch"]


def test_existing_ci03_identical_to_operator_upload():
    operator = Path("/mnt/data/03-postgres-integration.yml")
    if operator.is_file():
        reference = HERE / "reference/03-postgres-integration.original.yml"
        assert operator.read_bytes() == reference.read_bytes()


def _run_sha_gate(tmp_path, approved, input_sha, event_sha):
    import subprocess
    import os
    import yaml
    doc = yaml.load((HERE / ".github/workflows/05-p0-provenance-prep.yml").read_text(), Loader=yaml.BaseLoader)
    script = doc["jobs"]["p0-provenance-only"]["steps"][0]["run"]
    variables = os.environ.copy()
    variables.update({
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/ensaio/p0-schema-colaboracao-20261017",
        "GITHUB_REPOSITORY": "patroaiconsultech/efata-777-backend-premium-final-20260917",
        "GITHUB_SHA": event_sha,
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "P0_EXPECTED_REF": "refs/heads/ensaio/p0-schema-colaboracao-20261017",
        "P0_APPROVAL_PHRASE": "P0_PROVENIENCIA_SOMENTE",
        "P0_OPERATOR_SHA": input_sha,
        "P0_AO01_APPROVED_SHA": approved,
    })
    return subprocess.run(["bash", "-c", script], env=variables, capture_output=True, text=True)


def test_sha_gate_unset_repository_var_holds(tmp_path):
    revision = "a" * 40
    result = _run_sha_gate(tmp_path, "", revision, revision)
    assert result.returncode != 0
    assert "HOLD_APPROVED_SHA_UNSET_OR_INVALID" in result.stdout


def test_sha_gate_operator_input_mismatch_holds(tmp_path):
    result = _run_sha_gate(tmp_path, "a" * 40, "b" * 40, "a" * 40)
    assert result.returncode != 0
    assert "HOLD_SHA_NOT_APPROVED" in result.stdout


def test_sha_gate_different_event_commit_holds(tmp_path):
    result = _run_sha_gate(tmp_path, "a" * 40, "a" * 40, "b" * 40)
    assert result.returncode != 0
    assert "HOLD_EVENT_SHA_NOT_APPROVED" in result.stdout


def test_sha_gate_approved_exact_sha_passes_offline(tmp_path):
    revision = "a" * 40
    result = _run_sha_gate(tmp_path, revision, revision, revision)
    assert result.returncode == 0


def test_documentation_references_existing_paths():
    handoff = (HERE / "HANDOFF_AO01_GHA_PREP.md").read_text()
    assert "PATCH_CREATE_WORKFLOW_ONLY.diff" in handoff
    assert "docs/operations/P0_GHA_PREP_RUNBOOK.md" in handoff
    assert (HERE / "docs/operations/P0_GHA05_BOOTSTRAP_PUBLICACAO.md").is_file()
