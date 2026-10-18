#!/usr/bin/env python3
"""Check registry manifest bytes/platform; digest source remains a registry query.

Not a Docker execution, nor a security endorsement of the publisher.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys


def inspect_manifest(raw: bytes, reference: str) -> dict:
    allowlist = {
        "docker.io/library/postgres:18.6",
        "docker.io/library/python:3.12-slim-bookworm",
    }
    if reference not in allowlist:
        raise ValueError("IMAGE_TAG_NOT_ALLOWLISTED")
    content = json.loads(raw)
    if not isinstance(content, dict) or not isinstance(content.get("manifests"), list):
        raise ValueError("EXPECTED_MULTIARCH_OCI_INDEX")
    platforms = [
        {"os": m.get("platform", {}).get("os"), "architecture": m.get("platform", {}).get("architecture"),
         "digest": m.get("digest")}
        for m in content["manifests"] if isinstance(m, dict)
    ]
    if not any(p["os"] == "linux" and p["architecture"] == "amd64"
               and isinstance(p["digest"], str) and p["digest"].startswith("sha256:")
               and len(p["digest"]) == 71 for p in platforms):
        raise ValueError("NO_LINUX_AMD64_PLATFORM")
    digest = sha256(raw).hexdigest()
    return {
        "status": "REGISTRY_MANIFEST_CAPTURED_NOT_IMAGE_APPROVED",
        "tag_queried": reference,
        "registry": "docker.io",
        "immutable_ref_candidate": reference.rsplit(":", 1)[0] + "@sha256:" + digest,
        "manifest_sha256": digest,
        "platforms": platforms,
        "docker_image_run": False,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--reference", required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    try:
        result = inspect_manifest(a.manifest.read_bytes(), a.reference)
    except (ValueError, OSError, json.JSONDecodeError) as err:
        print("HOLD:", err, file=sys.stderr)
        return 1
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf8")
    print(result["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
