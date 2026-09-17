from __future__ import annotations

import tomllib
from pathlib import Path


def test_defusedxml_is_declared_as_runtime_dependency() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    dependencies = data["project"]["dependencies"]
    assert any(dep.lower().startswith("defusedxml") for dep in dependencies)
