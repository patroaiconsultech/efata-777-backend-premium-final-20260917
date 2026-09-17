from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Mapping

from .audit_file_adapter import AuditFileAdapter
from .audit_path_policy import AuditPathPolicy


class AuditRuntimeAdapterError(RuntimeError):
    code = "AUDIT_RUNTIME_MODULE_NOT_ALLOWED"


class AuditRuntimeAdapter:
    """Read-only inspection of an explicit server-owned module allowlist."""

    def __init__(
        self,
        *,
        project_root: Path,
        module_allowlist: Mapping[str, str],
        max_hash_bytes: int = 10_000_000,
        max_marker_scan_bytes: int = 1_000_000,
    ) -> None:
        self._policy = AuditPathPolicy({"runtime": project_root})
        self._allowlist = dict(module_allowlist)
        self._max_hash_bytes = max_hash_bytes
        self._file_adapter = AuditFileAdapter(
            max_marker_scan_bytes=max_marker_scan_bytes,
            max_secret_scan_bytes=max_hash_bytes,
        )

    def _relative_path(self, module_id: str) -> str:
        try:
            return self._allowlist[module_id]
        except KeyError as exc:
            raise AuditRuntimeAdapterError("AUDIT_RUNTIME_MODULE_NOT_ALLOWED") from exc

    def file_sha256(self, module_id: str) -> dict[str, object]:
        relative_path = self._relative_path(module_id)
        with self._policy.open_verified_file(
            root_id="runtime", relative_path=relative_path
        ) as verified:
            if verified.size > self._max_hash_bytes:
                raise AuditRuntimeAdapterError("AUDIT_RUNTIME_MODULE_TOO_LARGE")
            h = hashlib.sha256()
            offset = 0
            while offset < verified.size:
                chunk = os.pread(
                    verified.fd, min(64 * 1024, verified.size - offset), offset
                )
                if not chunk:
                    break
                h.update(chunk)
                offset += len(chunk)
            if offset != verified.size:
                raise AuditRuntimeAdapterError("AUDIT_RUNTIME_SHORT_READ")
            return {
                "module_id": module_id,
                "relative_path": verified.relative_path,
                "bytes_hashed": offset,
                "sha256": h.hexdigest(),
            }

    def search_marker(
        self,
        module_id: str,
        *,
        marker: str,
        max_scan_bytes: int = 1_000_000,
        max_matches: int = 256,
    ) -> dict[str, object]:
        relative_path = self._relative_path(module_id)
        with self._policy.open_verified_file(
            root_id="runtime", relative_path=relative_path
        ) as verified:
            result = self._file_adapter.find_literal_marker(
                verified,
                marker,
                max_scan_bytes=max_scan_bytes,
                max_matches=max_matches,
            )
            return {
                "module_id": module_id,
                "relative_path": verified.relative_path,
                **{
                    key: value
                    for key, value in result.items()
                    if key not in {"root_id", "relative_path"}
                },
            }
