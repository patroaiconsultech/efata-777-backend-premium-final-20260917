from __future__ import annotations

import os

import pytest

from orkio_v2.services.audit_path_policy import AuditPathPolicy, AuditPathPolicyError


def test_open_verified_file_binds_regular_file_identity(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "evidence.txt"
    target.write_text("hello", encoding="utf-8")
    policy = AuditPathPolicy({"evidence": root})
    with policy.open_verified_file(
        root_id="evidence", relative_path="evidence.txt"
    ) as verified:
        assert verified.relative_path == "evidence.txt"
        assert verified.size == 5
        assert os.pread(verified.fd, 5, 0) == b"hello"


def test_absolute_and_traversal_paths_are_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    policy = AuditPathPolicy({"evidence": root})
    for value in ("/etc/passwd", "../escape", "a/../../escape", r"a\..\escape"):
        with pytest.raises(AuditPathPolicyError):
            policy.open_verified_file(root_id="evidence", relative_path=value)


def test_symlink_source_is_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    real = root / "real.txt"
    real.write_text("secret", encoding="utf-8")
    link = root / "link.txt"
    link.symlink_to(real)
    policy = AuditPathPolicy({"evidence": root})
    with pytest.raises(AuditPathPolicyError):
        policy.open_verified_file(root_id="evidence", relative_path="link.txt")
