from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
import zipfile
from pathlib import PurePosixPath

from .audit_path_policy import VerifiedFile
from .audit_secret_policy import assert_no_high_confidence_secrets


class AuditArchiveError(RuntimeError):
    code = "AUDIT_ARCHIVE_ERROR"


_SECRET_LIKE_NAME = re.compile(
    r"(?:^|[._-])(?:secret|secrets|token|tokens|credential|credentials|private[_-]?key)(?:[._-]|$)",
    re.IGNORECASE,
)
_SECRET_LIKE_BASENAMES = {
    ".env",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "secrets.json",
}
_SECRET_LIKE_SUFFIXES = (".key", ".p12", ".pfx")
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _safe_member_name(name: str) -> str:
    if not name or "\\" in name or "\x00" in name:
        raise AuditArchiveError("AUDIT_ARCHIVE_UNSAFE_PATH")
    normalized = unicodedata.normalize("NFC", name)
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise AuditArchiveError("AUDIT_ARCHIVE_UNSAFE_PATH")
    return pure.as_posix()


def _assert_member_name_not_secret_like(name: str) -> None:
    basename = PurePosixPath(name).name.casefold()
    if (
        basename in _SECRET_LIKE_BASENAMES
        or basename.startswith(".env.")
        or basename.endswith(_SECRET_LIKE_SUFFIXES)
        or _SECRET_LIKE_NAME.search(basename)
    ):
        raise AuditArchiveError("AUDIT_ARCHIVE_SECRET_LIKE_MEMBER_FORBIDDEN")


def _decode_text_strict(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise AuditArchiveError("AUDIT_ARCHIVE_BINARY_AS_TEXT_FORBIDDEN") from exc
    if any(
        unicodedata.category(ch) == "Cc" and ch not in {"\t", "\n", "\r"}
        for ch in text
    ):
        raise AuditArchiveError("AUDIT_ARCHIVE_BINARY_AS_TEXT_FORBIDDEN")
    return text


class AuditArchiveAdapter:
    def __init__(
        self,
        *,
        max_entries: int = 512,
        max_member_bytes: int = 10_000_000,
        max_total_uncompressed_bytes: int = 50_000_000,
        max_stream_bytes: int = 10_000_000,
        max_compression_ratio: int = 200,
        max_nested_archive_depth: int = 0,
    ) -> None:
        if max_nested_archive_depth != 0:
            raise AuditArchiveError("AUDIT_ARCHIVE_NESTED_DEPTH_UNSUPPORTED")
        self.max_entries = max_entries
        self.max_member_bytes = max_member_bytes
        self.max_total_uncompressed_bytes = max_total_uncompressed_bytes
        self.max_stream_bytes = max_stream_bytes
        self.max_compression_ratio = max_compression_ratio
        self.max_nested_archive_depth = max_nested_archive_depth

    def _open_zip(self, verified: VerifiedFile):
        handle = os.fdopen(verified.duplicate_fd(), "rb")
        try:
            archive = zipfile.ZipFile(handle, "r")
        except Exception:
            handle.close()
            raise
        return handle, archive

    def _metadata_index(
        self, archive: zipfile.ZipFile
    ) -> tuple[list[tuple[str, zipfile.ZipInfo]], int]:
        infos = archive.infolist()
        if len(infos) > self.max_entries:
            raise AuditArchiveError("AUDIT_ARCHIVE_ENTRY_LIMIT_EXCEEDED")

        indexed: list[tuple[str, zipfile.ZipInfo]] = []
        seen_folded: set[str] = set()
        declared_total = 0

        for info in infos:
            name = _safe_member_name(info.filename.rstrip("/") or info.filename)
            folded = name.casefold()
            if folded in seen_folded:
                raise AuditArchiveError("AUDIT_ARCHIVE_DUPLICATE_PATH")
            seen_folded.add(folded)
            _assert_member_name_not_secret_like(name)

            mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode) if mode else 0
            if file_type == stat.S_IFLNK:
                raise AuditArchiveError("AUDIT_ARCHIVE_SYMLINK_FORBIDDEN")
            if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise AuditArchiveError("AUDIT_ARCHIVE_SPECIAL_FILE_FORBIDDEN")
            if info.flag_bits & 0x1:
                raise AuditArchiveError("AUDIT_ARCHIVE_ENCRYPTED_MEMBER_FORBIDDEN")
            if info.file_size > self.max_member_bytes:
                raise AuditArchiveError("AUDIT_ARCHIVE_MEMBER_TOO_LARGE")

            declared_total += int(info.file_size)
            if declared_total > self.max_total_uncompressed_bytes:
                raise AuditArchiveError("AUDIT_ARCHIVE_TOTAL_SIZE_EXCEEDED")
            if info.compress_size == 0:
                if info.file_size > 0:
                    raise AuditArchiveError("AUDIT_ARCHIVE_COMPRESSION_RATIO_EXCEEDED")
            elif info.file_size / info.compress_size > self.max_compression_ratio:
                raise AuditArchiveError("AUDIT_ARCHIVE_COMPRESSION_RATIO_EXCEEDED")
            indexed.append((name, info))

        return indexed, declared_total

    def _read_member_actual(
        self,
        archive: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        *,
        aggregate_before: int,
    ) -> tuple[bytes, int]:
        if info.is_dir():
            return b"", aggregate_before

        data = bytearray()
        actual_member = 0
        actual_total = aggregate_before
        try:
            with archive.open(info, "r") as stream:
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        break
                    actual_member += len(chunk)
                    actual_total += len(chunk)
                    if (
                        actual_member > self.max_member_bytes
                        or actual_member > self.max_stream_bytes
                    ):
                        raise AuditArchiveError("AUDIT_ARCHIVE_STREAM_LIMIT_EXCEEDED")
                    if actual_total > self.max_total_uncompressed_bytes:
                        raise AuditArchiveError("AUDIT_ARCHIVE_TOTAL_SIZE_EXCEEDED")
                    data.extend(chunk)
        except AuditArchiveError:
            raise
        except RuntimeError as exc:
            # zipfile can raise RuntimeError for encrypted/invalid members.
            raise AuditArchiveError("AUDIT_ARCHIVE_MEMBER_READ_FAILED") from exc

        raw = bytes(data)
        if raw.startswith(_ZIP_SIGNATURES):
            raise AuditArchiveError("AUDIT_ARCHIVE_NESTED_ARCHIVE_FORBIDDEN")
        assert_no_high_confidence_secrets(raw)
        if info.compress_size == 0:
            if actual_member > 0:
                raise AuditArchiveError("AUDIT_ARCHIVE_COMPRESSION_RATIO_EXCEEDED")
        elif actual_member / info.compress_size > self.max_compression_ratio:
            raise AuditArchiveError("AUDIT_ARCHIVE_COMPRESSION_RATIO_EXCEEDED")
        return raw, actual_total

    def preflight(self, verified: VerifiedFile) -> dict[str, object]:
        handle, archive = self._open_zip(verified)
        try:
            indexed, declared_total = self._metadata_index(archive)
            actual_total = 0
            entries: list[dict[str, object]] = []
            for name, info in indexed:
                raw, actual_total = self._read_member_actual(
                    archive, info, aggregate_before=actual_total
                )
                entries.append(
                    {
                        "name": name,
                        "uncompressed_bytes": int(info.file_size),
                        "actual_decompressed_bytes": len(raw),
                        "compressed_bytes": int(info.compress_size),
                        "crc32": f"{info.CRC:08x}",
                        "is_directory": info.is_dir(),
                    }
                )

            return {
                "root_id": verified.root_id,
                "relative_path": verified.relative_path,
                "entry_count": len(entries),
                "declared_total_uncompressed_bytes": declared_total,
                "actual_total_decompressed_bytes": actual_total,
                # compatibility alias retained for the first 033A tests.
                "total_uncompressed_bytes": actual_total,
                "nested_archive_max_depth": self.max_nested_archive_depth,
                "entries": entries,
            }
        except zipfile.BadZipFile as exc:
            raise AuditArchiveError("AUDIT_ARCHIVE_INVALID_ZIP") from exc
        finally:
            archive.close()
            handle.close()

    def manifest(
        self,
        verified: VerifiedFile,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, object]:
        if offset < 0 or limit < 1 or limit > self.max_entries:
            raise AuditArchiveError("AUDIT_ARCHIVE_MANIFEST_BOUNDS_INVALID")
        report = self.preflight(verified)
        entries = report["entries"]
        assert isinstance(entries, list)
        page = entries[offset : offset + limit]
        return {
            **{key: value for key, value in report.items() if key != "entries"},
            "manifest_offset": offset,
            "manifest_limit": limit,
            "returned_entries": len(page),
            "manifest_truncated": offset + len(page) < len(entries),
            "entries": page,
        }

    def _member_info(
        self, archive: zipfile.ZipFile, member_name: str
    ) -> tuple[str, zipfile.ZipInfo]:
        safe_name = _safe_member_name(member_name)
        indexed, _ = self._metadata_index(archive)
        by_name = {name: info for name, info in indexed}
        try:
            return safe_name, by_name[safe_name]
        except KeyError as exc:
            raise AuditArchiveError("AUDIT_ARCHIVE_MEMBER_NOT_FOUND") from exc

    def file_metadata(
        self,
        verified: VerifiedFile,
        *,
        member_name: str,
    ) -> dict[str, object]:
        report = self.preflight(verified)
        safe_name = _safe_member_name(member_name)
        for entry in report["entries"]:
            if entry["name"] == safe_name:
                return {
                    "root_id": verified.root_id,
                    "relative_path": verified.relative_path,
                    **entry,
                }
        raise AuditArchiveError("AUDIT_ARCHIVE_MEMBER_NOT_FOUND")

    def read_text_member(
        self,
        verified: VerifiedFile,
        *,
        member_name: str,
        offset: int = 0,
        max_bytes: int = 16_000,
    ) -> dict[str, object]:
        if offset < 0 or max_bytes < 1 or max_bytes > 64_000:
            raise AuditArchiveError("AUDIT_ARCHIVE_READ_BOUNDS_INVALID")
        self.preflight(verified)
        handle, archive = self._open_zip(verified)
        try:
            safe_name, info = self._member_info(archive, member_name)
            if info.is_dir():
                raise AuditArchiveError("AUDIT_ARCHIVE_MEMBER_NOT_FILE")
            raw, _ = self._read_member_actual(archive, info, aggregate_before=0)
            _decode_text_strict(raw)
            if offset > len(raw):
                raise AuditArchiveError("AUDIT_ARCHIVE_OFFSET_OUT_OF_RANGE")
            try:
                raw[:offset].decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise AuditArchiveError("AUDIT_ARCHIVE_UTF8_BOUNDARY_INVALID") from exc

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
                "member": safe_name,
                "offset": offset,
                "bytes_read": end - offset,
                "eof": end >= len(raw),
                "content": content,
            }
        finally:
            archive.close()
            handle.close()

    def hash_member(
        self,
        verified: VerifiedFile,
        *,
        member_name: str,
    ) -> dict[str, object]:
        self.preflight(verified)
        handle, archive = self._open_zip(verified)
        try:
            safe_name, info = self._member_info(archive, member_name)
            if info.is_dir():
                raise AuditArchiveError("AUDIT_ARCHIVE_MEMBER_NOT_FILE")
            raw, _ = self._read_member_actual(archive, info, aggregate_before=0)
            return {
                "root_id": verified.root_id,
                "relative_path": verified.relative_path,
                "member": safe_name,
                "actual_decompressed_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        except zipfile.BadZipFile as exc:
            raise AuditArchiveError("AUDIT_ARCHIVE_INVALID_ZIP") from exc
        finally:
            archive.close()
            handle.close()
