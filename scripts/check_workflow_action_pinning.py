from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
USES_RE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def iter_external_action_refs() -> list[tuple[Path, str]]:
    refs: list[tuple[Path, str]] = []
    for path in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        for match in USES_RE.finditer(text):
            ref = match.group(1).strip()
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            refs.append((path, ref))
    return refs


def main() -> int:
    violations: list[str] = []
    refs = iter_external_action_refs()

    for path, ref in refs:
        if "@" not in ref:
            violations.append(f"{path.relative_to(ROOT)}: missing @ref: {ref}")
            continue

        _, pinned_ref = ref.rsplit("@", 1)
        if not SHA_RE.fullmatch(pinned_ref):
            violations.append(
                f"{path.relative_to(ROOT)}: external action must use immutable 40-hex SHA: {ref}"
            )

    if violations:
        print("WORKFLOW_ACTION_PINNING=FAIL")
        for violation in violations:
            print(violation)
        return 1

    print(f"WORKFLOW_ACTION_PINNING=PASS refs={len(refs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
