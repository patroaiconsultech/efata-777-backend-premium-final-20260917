from __future__ import annotations

import hashlib

import pytest

from orkio_v2.services.audit_file_adapter import AuditFileAdapter, AuditFileAdapterError
from orkio_v2.services.audit_path_policy import AuditPathPolicy
from orkio_v2.services.audit_secret_policy import AuditSecretPolicyError


def _verified(tmp_path, data: bytes):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(data)
    policy = AuditPathPolicy({"e": root})
    return policy.open_verified_file(root_id="e", relative_path="a.txt")


def test_bounded_paginated_text_read_utf8_safe(tmp_path):
    with _verified(tmp_path, "AéBCD".encode("utf-8")) as verified:
        adapter = AuditFileAdapter(max_read_bytes=5)
        page = adapter.read_text(verified, offset=1, max_bytes=2)
        assert page["content"] == "é"
        assert page["bytes_read"] == 2
        assert page["eof"] is False

        with pytest.raises(AuditFileAdapterError, match="UTF8_BOUNDARY"):
            adapter.read_text(verified, offset=2, max_bytes=2)


def test_binary_as_text_is_denied(tmp_path):
    with _verified(tmp_path, b"hello\xffworld") as verified:
        with pytest.raises(AuditFileAdapterError, match="BINARY_AS_TEXT"):
            AuditFileAdapter().read_text(verified, max_bytes=64)

    control_root = tmp_path / "control"
    control_root.mkdir()
    (control_root / "a.txt").write_bytes(b"hello\x01world")
    policy = AuditPathPolicy({"e": control_root})
    with policy.open_verified_file(root_id="e", relative_path="a.txt") as verified:
        with pytest.raises(AuditFileAdapterError, match="BINARY_AS_TEXT"):
            AuditFileAdapter().read_text(verified, max_bytes=64)


def test_secret_content_is_blocked_for_every_page_boundary(tmp_path):
    secret = b"prefix:sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890:suffix"
    with _verified(tmp_path, secret) as verified:
        adapter = AuditFileAdapter(max_read_bytes=16)
        for offset in (0, 8, 16, 24, 32):
            with pytest.raises(
                AuditSecretPolicyError, match="AUDIT_SECRET_CONTENT_BLOCKED"
            ):
                adapter.read_text(verified, offset=offset, max_bytes=16)


def test_literal_marker_search_returns_frozen_audit_semantics(tmp_path):
    data = b"one TARGET\ntwo TARGET\nthree TARGET\n"
    with _verified(tmp_path, data) as verified:
        adapter = AuditFileAdapter(max_marker_scan_bytes=len(data))
        found = adapter.find_literal_marker(
            verified, "TARGET", max_scan_bytes=len(data), max_matches=2
        )
    assert found["marker_sha256"] == hashlib.sha256(b"TARGET").hexdigest()
    assert found["marker_found"] is True
    assert found["match_count"] == 3
    assert found["line_numbers"] == [1, 2]
    assert found["truncated_matches"] is True
    assert found["max_matches"] == 2
    assert found["scan_truncated"] is False
    assert found["match_count_complete"] is True


def test_marker_input_and_scan_bounds_are_fail_closed(tmp_path):
    with _verified(tmp_path, b"A" * 128) as verified:
        adapter = AuditFileAdapter(max_marker_scan_bytes=64)
        with pytest.raises(AuditFileAdapterError, match="SCAN_BOUNDS"):
            adapter.find_literal_marker(verified, "X", max_scan_bytes=65)
        with pytest.raises(AuditFileAdapterError, match="CONTROL_CHAR"):
            adapter.find_literal_marker(verified, "X\nY", max_scan_bytes=64)
        with pytest.raises(AuditFileAdapterError, match="CONTROL_CHAR"):
            adapter.find_literal_marker(verified, "X\x85Y", max_scan_bytes=64)
        with pytest.raises(AuditFileAdapterError, match="BOUNDS"):
            adapter.find_literal_marker(verified, "é" * 257, max_scan_bytes=64)

        result = adapter.find_literal_marker(
            verified, "A", max_scan_bytes=64, max_matches=10
        )
        assert result["scan_truncated"] is True
        assert result["match_count_complete"] is False
