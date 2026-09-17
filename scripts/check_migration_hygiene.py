from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ROOT / "migrations" / "versions"

# Revision 001 is a known historical exception tracked as EFATA-AUD-001.
GRANDFATHERED = {"001_v2_foundation.py"}
FORBIDDEN = (
    re.compile(r"\bBase\.metadata\.create_all\s*\("),
    re.compile(r"\bBase\.metadata\.drop_all\s*\("),
)


def main() -> int:
    violations: list[str] = []
    for path in sorted(VERSIONS.glob("*.py")):
        if path.name.startswith("__") or path.name in GRANDFATHERED:
            continue
        text = path.read_text(encoding="utf-8")
        if any(pattern.search(text) for pattern in FORBIDDEN):
            violations.append(path.name)

    if violations:
        print("MIGRATION_HYGIENE_FAILED")
        for name in violations:
            print(f"- {name}: ORM metadata bootstrap is forbidden in new revisions")
        return 1

    known = VERSIONS / "001_v2_foundation.py"
    if known.exists() and any(pattern.search(known.read_text(encoding="utf-8")) for pattern in FORBIDDEN):
        print("MIGRATION_HYGIENE_PASS_WITH_KNOWN_DEBT=EFATA-AUD-001")
    else:
        print("MIGRATION_HYGIENE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
