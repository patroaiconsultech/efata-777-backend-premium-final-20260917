#!/usr/bin/env python3
"""Validate only downloaded *binary* wheels against the B39 hash-pinned lock.

No database, network, Docker, imports of wheel content, or subprocesses.
Only proves integrity + interpreter tag compatibility for existing files.
Explicitly verifies completeness of applicable lock entries; resolution and installation
are additionally tested by offline pip install.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import sys

try:
    from packaging.tags import sys_tags
    from packaging.markers import Marker, default_environment
    from packaging.utils import canonicalize_name, parse_wheel_filename
except ImportError:  # pip vendors packaging in a managed Python environment
    from pip._vendor.packaging.tags import sys_tags
    from pip._vendor.packaging.markers import Marker, default_environment
    from pip._vendor.packaging.utils import canonicalize_name, parse_wheel_filename

LOCK_ENTRY = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)(?:\s*;\s*([^\\\n]+))?", re.M)
SHA = re.compile(r"--hash=sha256:([a-fA-F0-9]{64})")


def read_lock(path: Path) -> dict[str, tuple[str, set[str], str | None]]:
    raw = path.read_text(encoding="utf-8")
    matches = list(LOCK_ENTRY.finditer(raw))
    if not matches:
        raise ValueError("EMPTY_OR_NONPINNED_LOCK")
    result = {}
    for i, match in enumerate(matches):
        name = canonicalize_name(match.group(1))
        version = match.group(2)
        chunk = raw[match.end(): matches[i + 1].start() if i + 1 < len(matches) else len(raw)]
        hashes = set(SHA.findall(chunk))
        if not hashes:
            raise ValueError("LOCK_WITHOUT_HASH:" + name)
        if name in result:
            raise ValueError("DUPLICATE_PACKAGE:" + name)
        marker = match.group(3).strip() if match.group(3) else None
        if marker:
            Marker(marker)  # Reject malformed platform markers, fail closed.
        result[name] = (version, hashes, marker)
    return result


def validate(lock: Path, wheelhouse: Path, expected_lock_sha256: str) -> dict:
    digest = sha256(lock.read_bytes()).hexdigest()
    if digest != expected_lock_sha256:
        raise ValueError("LOCK_SHA256_MISMATCH")
    if sys.version_info[:2] != (3, 12):
        raise ValueError("PYTHON_MUST_BE_3_12")
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise ValueError("PLATFORM_MUST_BE_LINUX_AMD64")
    wheel_tags = set(sys_tags())
    if not wheel_tags:
        raise ValueError("NO_INTERPRETER_TAGS")
    locked = read_lock(lock)
    # Evaluate PEP 508 markers for the actual Linux x86_64 / CPython 3.12
    # target. Keep this explicit even when the test suite mocks sys_tags().
    environment = default_environment()
    environment.update({
        "python_version": "3.12",
        "python_full_version": ".".join(map(str, sys.version_info[:3])),
        "sys_platform": "linux",
        "os_name": "posix",
        "platform_machine": "x86_64",
        "implementation_name": "cpython",
        "platform_python_implementation": "CPython",
    })
    applicable = {
        name: (version, hashes)
        for name, (version, hashes, marker) in locked.items()
        if not marker or Marker(marker).evaluate(environment=environment)
    }
    if not applicable:
        raise ValueError("EMPTY_APPLICABLE_LOCK")
    files = list(wheelhouse.iterdir())
    if not files:
        raise ValueError("EMPTY_WHEELHOUSE")
    seen = set()
    report = []
    for wheel in sorted(files):
        if wheel.is_symlink() or not wheel.is_file() or wheel.suffix != ".whl":
            raise ValueError("UNEXPECTED_FILE:" + wheel.name)
        name, version, build, tags = parse_wheel_filename(wheel.name)
        key = canonicalize_name(name)
        if key not in applicable:
            raise ValueError("UNDECLARED_OR_INACTIVE_WHEEL:" + wheel.name)
        expected_version, expected_hashes = applicable[key]
        if str(version) != expected_version:
            raise ValueError("VERSION_MISMATCH:" + wheel.name)
        if key in seen:
            raise ValueError("MULTIPLE_WHEELS_FOR_PACKAGE:" + key)
        seen.add(key)
        match = wheel_tags.intersection(tags)
        if not match:
            raise ValueError("INCOMPATIBLE_TAGS:" + wheel.name)
        wheel_hash = sha256(wheel.read_bytes()).hexdigest()
        if wheel_hash not in expected_hashes:
            raise ValueError("WHEEL_HASH_NOT_IN_LOCK:" + wheel.name)
        report.append({
            "name": key,
            "version": str(version),
            "filename": wheel.name,
            "sha256": wheel_hash,
            "matched_tag": str(sorted(match, key=str)[0]),
        })
    missing = sorted(set(applicable) - seen)
    if missing:
        raise ValueError("MISSING_WHEELS_FOR_LOCK:" + ",".join(missing))
    if seen != set(applicable):
        raise ValueError("WHEELHOUSE_SET_MISMATCH")
    return {
        "status": "PASS_STATIC_WHEELHOUSE_COMPLETE_TAGS_AND_HASHES",
        "lock_sha256": digest,
        "python": ".".join(map(str, sys.version_info[:3])),
        "platform": platform.platform(),
        "supported_tag_count": len(wheel_tags),
        "lock_package_count": len(locked),
        "applicable_package_count": len(applicable),
        "excluded_by_marker": sorted(set(locked) - set(applicable)),
        "wheel_count": len(report),
        "complete_against_applicable_lock": True,
        "installed_or_resolved_offline": False,
        "wheels": report,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--expected-lock-sha256", required=True)
    args = parser.parse_args()
    try:
        report = validate(args.lock, args.wheelhouse, args.expected_lock_sha256)
    except (ValueError, OSError) as exc:
        print("HOLD:", str(exc), file=sys.stderr)
        return 1
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(report["status"], "wheels=", len(report["wheels"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
