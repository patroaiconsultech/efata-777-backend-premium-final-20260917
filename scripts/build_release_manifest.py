from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    return hashlib.sha256(data).hexdigest()


def git(*args: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", *args],
            cwd=ROOT,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip() or None
    except Exception:
        return None


def migration_head() -> str | None:
    versions = ROOT / "migrations" / "versions"
    if not versions.is_dir():
        return None
    revisions: list[tuple[str, str | None]] = []
    for path in versions.glob("*.py"):
        if path.name.startswith("__"):
            continue
        text = path.read_text(encoding="utf-8")
        revision = None
        down_revision = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("revision") and "=" in stripped:
                revision = stripped.split("=", 1)[1].strip().strip("\"'")
            if stripped.startswith("down_revision") and "=" in stripped:
                raw = stripped.split("=", 1)[1].strip()
                down_revision = None if raw == "None" else raw.strip("\"'")
        if revision:
            revisions.append((revision, down_revision))
    referenced = {down for _, down in revisions if down}
    heads = sorted(rev for rev, _ in revisions if rev not in referenced)
    return heads[0] if len(heads) == 1 else ",".join(heads) if heads else None


def main() -> None:
    dirty = git("status", "--porcelain")
    manifest = {
        "product": "PatroAI Platform",
        "component": "backend",
        "repository": os.getenv("GITHUB_REPOSITORY"),
        "branch": os.getenv("GITHUB_REF_NAME") or git("branch", "--show-current"),
        "commit_sha": os.getenv("GITHUB_SHA") or git("rev-parse", "HEAD"),
        "dirty_tree": bool(dirty) if dirty is not None else None,
        "ci_run_id": os.getenv("GITHUB_RUN_ID"),
        "build_timestamp": datetime.now(timezone.utc).isoformat(),
        "migration_head": migration_head(),
        "locks": {
            "requirements_lock_sha256": sha256(ROOT / "requirements.lock.txt"),
            "uv_lock_sha256": sha256(ROOT / "uv.lock"),
        },
    }
    output = ROOT / "build-evidence" / "release-manifest.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("BACKEND_RELEASE_MANIFEST=PASS")


if __name__ == "__main__":
    main()
