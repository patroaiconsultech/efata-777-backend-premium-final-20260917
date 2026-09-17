from __future__ import annotations

import subprocess

import pytest

from orkio_v2.services.capability_policy import CapabilityPolicy, CapabilityPolicyError
from orkio_v2.services.python_tool import PythonToolDisabled, execute_python


def _set_legacy_flags(monkeypatch):
    monkeypatch.setenv("PLATFORM_PYTHON_TOOL_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_MODE", "legacy_local_test")
    monkeypatch.setenv("PLATFORM_PYTHON_LEGACY_LOCAL_TEST_ENABLED", "true")
    monkeypatch.setenv("PLATFORM_PYTHON_RUNTIME_ADAPTER", "unconfigured")


def _spy_subprocess(monkeypatch):
    calls = {"count": 0}

    def fake_run(*args, **kwargs):
        calls["count"] += 1
        return subprocess.CompletedProcess(
            args=args[0] if args else None,
            returncode=0,
            stdout=b"42\n",
            stderr=b"",
        )

    monkeypatch.setattr(
        "orkio_v2.services.python_tool.subprocess.run",
        fake_run,
    )
    return calls


@pytest.mark.asyncio
async def test_r5b1_missing_environment_fails_closed_without_subprocess(monkeypatch):
    _set_legacy_flags(monkeypatch)
    monkeypatch.delenv("PLATFORM_ENVIRONMENT", raising=False)
    monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    calls = _spy_subprocess(monkeypatch)

    policy = CapabilityPolicy.from_env()
    assert policy.python_runtime_environment == "unknown"
    with pytest.raises(PythonToolDisabled, match="PYTHON_LEGACY_RUNTIME_FORBIDDEN"):
        await execute_python("print(42)", policy)
    assert calls["count"] == 0


@pytest.mark.asyncio
async def test_r5b1_invalid_platform_environment_errors_before_subprocess(monkeypatch):
    _set_legacy_flags(monkeypatch)
    monkeypatch.setenv("PLATFORM_ENVIRONMENT", "prodution")
    monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    calls = _spy_subprocess(monkeypatch)

    with pytest.raises(CapabilityPolicyError, match="PLATFORM_ENVIRONMENT_INVALID"):
        CapabilityPolicy.from_env()
    assert calls["count"] == 0


@pytest.mark.asyncio
async def test_r5b1_arbitrary_railway_environment_does_not_become_development(monkeypatch):
    _set_legacy_flags(monkeypatch)
    monkeypatch.delenv("PLATFORM_ENVIRONMENT", raising=False)
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "sandbox-temp")
    calls = _spy_subprocess(monkeypatch)

    policy = CapabilityPolicy.from_env()
    assert policy.python_runtime_environment == "unknown"
    with pytest.raises(PythonToolDisabled, match="PYTHON_LEGACY_RUNTIME_FORBIDDEN"):
        await execute_python("print(42)", policy)
    assert calls["count"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("environment", ["staging", "production"])
async def test_r5b1_staging_and_production_never_run_legacy_subprocess(
    monkeypatch, environment
):
    _set_legacy_flags(monkeypatch)
    monkeypatch.setenv("PLATFORM_ENVIRONMENT", environment)
    monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    calls = _spy_subprocess(monkeypatch)

    policy = CapabilityPolicy.from_env()
    assert policy.python_runtime_environment == environment
    with pytest.raises(PythonToolDisabled, match="PYTHON_LEGACY_RUNTIME_FORBIDDEN"):
        await execute_python("print(42)", policy)
    assert calls["count"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("environment", ["development", "test"])
async def test_r5b1_explicit_dev_test_with_legacy_flags_allows_local_executor(
    monkeypatch, environment
):
    _set_legacy_flags(monkeypatch)
    monkeypatch.setenv("PLATFORM_ENVIRONMENT", environment)
    monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    calls = _spy_subprocess(monkeypatch)

    policy = CapabilityPolicy.from_env()
    result = await execute_python("print(42)", policy)
    assert result.stdout == "42\n"
    assert calls["count"] == 1


@pytest.mark.parametrize(
    ("railway_name", "expected"),
    [
        ("staging-v3", "staging"),
        ("production-blue", "production"),
        ("test-sandbox", "test"),
        ("dev-local", "development"),
        ("prodution", "unknown"),
        ("sandbox-temp", "unknown"),
        ("production-staging", "unknown"),
    ],
)
def test_r5b1_railway_normalization_is_conservative(
    monkeypatch, railway_name, expected
):
    monkeypatch.delenv("PLATFORM_ENVIRONMENT", raising=False)
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", railway_name)
    policy = CapabilityPolicy.from_env()
    assert policy.python_runtime_environment == expected
