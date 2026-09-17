#!/usr/bin/env python3
"""Generate deterministic release evidence for the backend tree.

The manifest intentionally contains no wall-clock timestamp. It is derived from
one checkout, one git SHA, and one sorted file tree so a second run over the same
source produces byte-identical JSON and SHA256SUMS output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "build-evidence",
    "build-security",
    "dist",
}
EXCLUDED_NAMES = {
    "release-manifest.json",
    "SHA256SUMS",
}


def git_sha(root: Path) -> str:
    try:
        value = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        value = "unknown"
    return value or "unknown"


def included_files(root: Path) -> list[Path]:
    result: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.name in EXCLUDED_NAMES:
            continue
        result.append(relative)
    return sorted(result, key=lambda item: item.as_posix())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--sums", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    manifest = args.manifest.resolve()
    sums = args.sums.resolve()
    entries = []
    for relative in included_files(root):
        absolute = root / relative
        entries.append(
            {
                "path": relative.as_posix(),
                "bytes": absolute.stat().st_size,
                "sha256": sha256(absolute),
            }
        )

    payload = {
        "schema": "efata.release-manifest.v1",
        "repository": "Plataforma-Efata-777-Backend",
        "git_sha": git_sha(root),
        "file_count": len(entries),
        "files": entries,
    }
    manifest.parent.mkdir(parents=True, exist_ok=True)
    sums.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    sums.write_text(
        "".join(f"{item['sha256']}  {item['path']}\n" for item in entries),
        encoding="utf-8",
    )
    print(json.dumps({"manifest": str(manifest), "sums": str(sums), "file_count": len(entries)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

