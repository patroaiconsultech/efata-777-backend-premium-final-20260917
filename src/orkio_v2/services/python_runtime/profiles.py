from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json


class PythonRuntimeProfileError(RuntimeError):
    code = "PYTHON_RUNTIME_PROFILE_ERROR"


@dataclass(frozen=True, slots=True)
class PythonRuntimeProfile:
    profile_id: str
    python_version: str
    packages: tuple[str, ...]
    allowed_imports: tuple[str, ...]
    capabilities: tuple[str, ...]
    network_policy: str
    filesystem_policy: str
    version: int

    @property
    def digest(self) -> str:
        payload = json.dumps(
            asdict(self),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


_PROFILES: dict[str, PythonRuntimeProfile] = {
    "python-analysis-lite-v1": PythonRuntimeProfile(
        profile_id="python-analysis-lite-v1",
        python_version="3.12.3",
        packages=(),
        allowed_imports=(
            "datetime",
            "decimal",
            "fractions",
            "json",
            "math",
            "statistics",
        ),
        capabilities=(
            "calculation",
            "structured_text",
            "json",
            "csv_text",
        ),
        network_policy="DENY",
        filesystem_policy="EPHEMERAL_ISOLATED",
        version=1,
    ),
}


def get_runtime_profile(profile_id: str) -> PythonRuntimeProfile:
    profile = _PROFILES.get((profile_id or "").strip())
    if profile is None:
        raise PythonRuntimeProfileError("PYTHON_RUNTIME_PROFILE_UNKNOWN")
    return profile


def runtime_profile_manifest(profile_id: str) -> dict[str, object]:
    profile = get_runtime_profile(profile_id)
    return {
        "profile_id": profile.profile_id,
        "python_version": profile.python_version,
        "packages": list(profile.packages),
        "allowed_imports": list(profile.allowed_imports),
        "capabilities": list(profile.capabilities),
        "network_policy": profile.network_policy,
        "filesystem_policy": profile.filesystem_policy,
        "version": profile.version,
        "digest": profile.digest,
    }
