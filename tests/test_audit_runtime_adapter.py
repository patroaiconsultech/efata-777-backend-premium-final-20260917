from __future__ import annotations

import hashlib

import pytest

from orkio_v2.services.audit_runtime_adapter import (
    AuditRuntimeAdapter,
    AuditRuntimeAdapterError,
)


def test_allowlisted_runtime_sha_and_marker_are_separate_operations(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    data = b"def run():\n    return 'ok'\n# return marker\n"
    (root / "module.py").write_bytes(data)
    adapter = AuditRuntimeAdapter(
        project_root=root,
        module_allowlist={"core": "module.py"},
    )

    hashed = adapter.file_sha256("core")
    searched = adapter.search_marker("core", marker="return", max_matches=256)

    assert hashed["sha256"] == hashlib.sha256(data).hexdigest()
    assert hashed["bytes_hashed"] == len(data)
    assert searched["marker_sha256"] == hashlib.sha256(b"return").hexdigest()
    assert searched["match_count"] == 2
    assert searched["line_numbers"] == [2, 3]
    assert searched["truncated_matches"] is False
    assert searched["match_count_complete"] is True


def test_unallowlisted_runtime_module_is_denied_for_both_surfaces(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    adapter = AuditRuntimeAdapter(project_root=root, module_allowlist={})
    with pytest.raises(AuditRuntimeAdapterError, match="MODULE_NOT_ALLOWED"):
        adapter.file_sha256("../../etc/passwd")
    with pytest.raises(AuditRuntimeAdapterError, match="MODULE_NOT_ALLOWED"):
        adapter.search_marker("../../etc/passwd", marker="root")
