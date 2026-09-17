from __future__ import annotations

import hashlib
import os
import unicodedata

from .audit_path_policy import VerifiedFile
from .audit_secret_policy import assert_no_high_confidence_secrets


class AuditFileAdapterError(RuntimeError):
    code = "AUDIT_FILE_ERROR"


def _validate_marker(marker: str, *, max_marker_bytes: int) -> bytes:
    raw = marker.encode("utf-8")
    if not raw or len(raw) > max_marker_bytes:
        raise AuditFileAdapterError("AUDIT_MARKER_BOUNDS_INVALID")
    if any(unicodedata.category(ch) == "Cc" for ch in marker):
        raise AuditFileAdapterError("AUDIT_MARKER_CONTROL_CHAR_FORBIDDEN")
    assert_no_high_confidence_secrets(raw)
    return raw


def _decode_text_strict(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise AuditFileAdapterError("AUDIT_FILE_BINARY_AS_TEXT_FORBIDDEN") from exc
    if any(
        unicodedata.category(ch) == "Cc" and ch not in {"\t", "\n", "\r"}
        for ch in text
    ):
        raise AuditFileAdapterError("AUDIT_FILE_BINARY_AS_TEXT_FORBIDDEN")
    return text


class AuditFileAdapter:
    def __init__(
        self,
        *,
        max_read_bytes: int = 64_000,
        max_marker_bytes: int = 512,
        max_marker_scan_bytes: int = 1_000_000,
        max_secret_scan_bytes: int = 10_000_000,
    ) -> None:
        self.max_read_bytes = max_read_bytes
        self.max_marker_bytes = max_marker_bytes
        self.max_marker_scan_bytes = max_marker_scan_bytes
        self.max_secret_scan_bytes = max_secret_scan_bytes

    def _read_full_safe_text(self, verified: VerifiedFile) -> tuple[bytes, str]:
        if verified.size > self.max_secret_scan_bytes:
            raise AuditFileAdapterError("AUDIT_FILE_SECRET_SCAN_LIMIT_EXCEEDED")
        raw = os.pread(verified.fd, verified.size, 0)
        if len(raw) != verified.size:
            raise AuditFileAdapterError("AUDIT_FILE_SHORT_READ")
        assert_no_high_confidence_secrets(raw)
        return raw, _decode_text_strict(raw)

    def file_metadata(self, verified: VerifiedFile) -> dict[str, object]:
        return {
            "root_id": verified.root_id,
            "relative_path": verified.relative_path,
            "size_bytes": verified.size,
            "device": verified.device,
            "inode": verified.inode,
        }

    def read_text(
        self,
        verified: VerifiedFile,
        *,
        offset: int = 0,
        max_bytes: int = 16_000,
        limit: int | None = None,
    ) -> dict[str, object]:
        # `limit` is retained only as a local compatibility alias. The frozen
        # request contract uses `max_bytes`.
        if limit is not None:
            max_bytes = limit
        if offset < 0 or max_bytes < 1 or max_bytes > self.max_read_bytes:
            raise AuditFileAdapterError("AUDIT_FILE_READ_BOUNDS_INVALID")

        raw, _ = self._read_full_safe_text(verified)
        if offset > len(raw):
            raise AuditFileAdapterError("AUDIT_FILE_OFFSET_OUT_OF_RANGE")
        try:
            raw[:offset].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise AuditFileAdapterError("AUDIT_FILE_UTF8_BOUNDARY_INVALID") from exc

        end = min(len(raw), offset + max_bytes)
        while end > offset:
            try:
                content = raw[offset:end].decode("utf-8", "strict")
                break
            except UnicodeDecodeError:
                end -= 1
        else:
            content = ""

        return {
            "root_id": verified.root_id,
            "relative_path": verified.relative_path,
            "offset": offset,
            "bytes_read": end - offset,
            "eof": end >= len(raw),
            "content": content,
        }

    def find_literal_marker(
        self,
        verified: VerifiedFile,
        marker: str,
        *,
        max_scan_bytes: int | None = None,
        max_matches: int = 256,
    ) -> dict[str, object]:
        marker_raw = _validate_marker(marker, max_marker_bytes=self.max_marker_bytes)
        scan_limit = (
            self.max_marker_scan_bytes if max_scan_bytes is None else max_scan_bytes
        )
        if scan_limit < 1 or scan_limit > self.max_marker_scan_bytes:
            raise AuditFileAdapterError("AUDIT_MARKER_SCAN_BOUNDS_INVALID")
        if max_matches < 1 or max_matches > 256:
            raise AuditFileAdapterError("AUDIT_MARKER_MATCH_BOUNDS_INVALID")

        raw, _ = self._read_full_safe_text(verified)
        scan_raw = raw[: min(len(raw), scan_limit)]

        offsets: list[int] = []
        cursor = 0
        while True:
            index = scan_raw.find(marker_raw, cursor)
            if index < 0:
                break
            offsets.append(index)
            cursor = index + max(1, len(marker_raw))

        visible = offsets[:max_matches]
        line_numbers = [scan_raw.count(b"\n", 0, index) + 1 for index in visible]
        scan_truncated = len(raw) > len(scan_raw)
        return {
            "root_id": verified.root_id,
            "relative_path": verified.relative_path,
            "marker_sha256": hashlib.sha256(marker_raw).hexdigest(),
            "marker_found": bool(offsets),
            "match_count": len(offsets),
            "line_numbers": line_numbers,
            "truncated_matches": len(offsets) > len(visible),
            "max_matches": max_matches,
            "bytes_scanned": len(scan_raw),
            "scan_truncated": scan_truncated,
            "match_count_complete": not scan_truncated,
        }
