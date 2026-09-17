from __future__ import annotations

import zipfile
from dataclasses import dataclass
from typing import Any

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException


_DEFAULT_MAX_ARCHIVE_ENTRIES = 512
_DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES = 64_000_000
_DEFAULT_MAX_MEMBER_UNCOMPRESSED_BYTES = 16_000_000
_DEFAULT_DOCX_MAX_XML_BYTES = 2_000_000


@dataclass(frozen=True)
class ArchiveSecurityLimits:
    max_entries: int
    max_total_uncompressed_bytes: int
    max_member_uncompressed_bytes: int


@dataclass(frozen=True)
class DocumentIngestionSecurityPolicy:
    archive: ArchiveSecurityLimits
    docx_max_xml_bytes: int


@dataclass(frozen=True)
class ArchiveInspection:
    entry_count: int
    total_uncompressed_bytes: int
    largest_member_bytes: int
    maximum_compression_ratio: float


class DocumentIngestionSecurityError(RuntimeError):
    code = "DOCUMENT_INGESTION_SECURITY_ERROR"

    def __init__(
        self,
        *,
        details: dict[str, int | float | str] | None = None,
    ) -> None:
        self.details = dict(details or {})
        super().__init__(self.code)

    def safe_details(self) -> dict[str, int | float | str]:
        allowed = {
            "archive_entry_count",
            "archive_total_uncompressed_bytes",
            "archive_largest_member_bytes",
            "archive_maximum_compression_ratio",
            "archive_duplicate_count",
            "configured_limit",
        }

        result: dict[str, int | float | str] = {}

        for key, value in self.details.items():
            if key in allowed:
                result[f"ingestion_{key}"] = value

        return result


class ArchiveEntryLimitExceeded(DocumentIngestionSecurityError):
    code = "DOCUMENT_ARCHIVE_ENTRY_LIMIT_EXCEEDED"


class ArchiveTotalSizeExceeded(DocumentIngestionSecurityError):
    code = "DOCUMENT_ARCHIVE_TOTAL_SIZE_EXCEEDED"


class ArchiveMemberTooLarge(DocumentIngestionSecurityError):
    code = "DOCUMENT_ARCHIVE_MEMBER_TOO_LARGE"


class ArchiveDuplicateMember(DocumentIngestionSecurityError):
    code = "DOCUMENT_ARCHIVE_DUPLICATE_MEMBER"


class ArchiveRequiredMemberInvalid(DocumentIngestionSecurityError):
    code = "DOCUMENT_ARCHIVE_REQUIRED_MEMBER_INVALID"


class ArchivePathRejected(DocumentIngestionSecurityError):
    code = "DOCUMENT_ARCHIVE_PATH_REJECTED"


class UnsafeXmlRejected(DocumentIngestionSecurityError):
    code = "DOCUMENT_XML_UNSAFE"


class InvalidXml(DocumentIngestionSecurityError):
    code = "DOCUMENT_XML_INVALID"


def default_document_ingestion_policy() -> DocumentIngestionSecurityPolicy:
    return DocumentIngestionSecurityPolicy(
        archive=ArchiveSecurityLimits(
            max_entries=_DEFAULT_MAX_ARCHIVE_ENTRIES,
            max_total_uncompressed_bytes=(
                _DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES
            ),
            max_member_uncompressed_bytes=(
                _DEFAULT_MAX_MEMBER_UNCOMPRESSED_BYTES
            ),
        ),
        docx_max_xml_bytes=_DEFAULT_DOCX_MAX_XML_BYTES,
    )


def _validate_archive_member_name(name: str) -> None:
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
    ):
        raise ArchivePathRejected()

    segments = name.split("/")

    if any(segment in {".", ".."} for segment in segments):
        raise ArchivePathRejected()

    # Empty internal path components are rejected.
    # A final empty component is permitted for directory entries.
    if any(segment == "" for segment in segments[:-1]):
        raise ArchivePathRejected()

    if segments and ":" in segments[0]:
        raise ArchivePathRejected()


def inspect_zip_archive(
    archive: zipfile.ZipFile,
    *,
    limits: ArchiveSecurityLimits,
    required_members: tuple[str, ...] = (),
) -> ArchiveInspection:
    infos = archive.infolist()

    entry_count = len(infos)

    if entry_count > limits.max_entries:
        raise ArchiveEntryLimitExceeded(
            details={
                "archive_entry_count": entry_count,
                "configured_limit": limits.max_entries,
            }
        )

    seen: set[str] = set()
    duplicate_count = 0
    total_uncompressed = 0
    largest_member = 0
    maximum_ratio = 0.0

    for info in infos:
        name = info.filename

        _validate_archive_member_name(name)

        if name in seen:
            duplicate_count += 1
        else:
            seen.add(name)

        member_size = max(0, int(info.file_size))
        compressed_size = max(0, int(info.compress_size))

        if member_size > limits.max_member_uncompressed_bytes:
            raise ArchiveMemberTooLarge(
                details={
                    "archive_entry_count": entry_count,
                    "archive_largest_member_bytes": member_size,
                    "configured_limit": (
                        limits.max_member_uncompressed_bytes
                    ),
                }
            )

        total_uncompressed += member_size
        largest_member = max(
            largest_member,
            member_size,
        )

        ratio = (
            member_size / max(1, compressed_size)
            if member_size
            else 0.0
        )

        maximum_ratio = max(
            maximum_ratio,
            ratio,
        )

        if (
            total_uncompressed
            > limits.max_total_uncompressed_bytes
        ):
            raise ArchiveTotalSizeExceeded(
                details={
                    "archive_entry_count": entry_count,
                    "archive_total_uncompressed_bytes": (
                        total_uncompressed
                    ),
                    "archive_largest_member_bytes": (
                        largest_member
                    ),
                    "archive_maximum_compression_ratio": round(
                        maximum_ratio,
                        2,
                    ),
                    "configured_limit": (
                        limits.max_total_uncompressed_bytes
                    ),
                }
            )

    if duplicate_count:
        raise ArchiveDuplicateMember(
            details={
                "archive_entry_count": entry_count,
                "archive_duplicate_count": duplicate_count,
            }
        )

    for required in required_members:
        if required not in seen:
            raise ArchiveRequiredMemberInvalid(
                details={
                    "archive_entry_count": entry_count,
                }
            )

    return ArchiveInspection(
        entry_count=entry_count,
        total_uncompressed_bytes=total_uncompressed,
        largest_member_bytes=largest_member,
        maximum_compression_ratio=round(
            maximum_ratio,
            2,
        ),
    )


def read_zip_member_bounded(
    archive: zipfile.ZipFile,
    member: str,
    *,
    max_bytes: int,
) -> bytes:
    info = archive.getinfo(member)

    if info.file_size > max_bytes:
        raise ArchiveMemberTooLarge(
            details={
                "archive_largest_member_bytes": int(
                    info.file_size
                ),
                "configured_limit": max_bytes,
            }
        )

    with archive.open(info, "r") as source:
        raw = source.read(max_bytes + 1)

    if len(raw) > max_bytes:
        raise ArchiveMemberTooLarge(
            details={
                "archive_largest_member_bytes": len(raw),
                "configured_limit": max_bytes,
            }
        )

    return raw


def parse_untrusted_xml(raw: bytes) -> Any:
    try:
        return DefusedET.fromstring(
            raw,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except DefusedXmlException as exc:
        raise UnsafeXmlRejected() from exc
    except DefusedET.ParseError as exc:
        raise InvalidXml() from exc
