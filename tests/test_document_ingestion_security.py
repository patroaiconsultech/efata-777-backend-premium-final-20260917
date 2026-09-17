from __future__ import annotations

import io
import warnings
import zipfile

import pytest
from pydantic import ValidationError

from orkio_v2.config import Settings
from orkio_v2.services.document_context import (
    DocumentContextError,
    DocumentExtractionFailed,
    DocumentIntegrityError,
    _security_error_details,
    extract_document_text,
)
from orkio_v2.services.document_ingestion_security import (
    ArchiveDuplicateMember,
    ArchiveEntryLimitExceeded,
    ArchiveMemberTooLarge,
    ArchivePathRejected,
    ArchiveSecurityLimits,
    ArchiveTotalSizeExceeded,
    DocumentIngestionSecurityPolicy,
    UnsafeXmlRejected,
    default_document_ingestion_policy,
    inspect_zip_archive,
    parse_untrusted_xml,
    read_zip_member_bounded,
)


DOCX_MIME = (
    "application/vnd.openxmlformats-officedocument."
    "wordprocessingml.document"
)

WORD_NS = (
    "http://schemas.openxmlformats.org/"
    "wordprocessingml/2006/main"
)


def _archive_bytes(
    members: list[tuple[str, bytes]],
) -> bytes:
    output = io.BytesIO()

    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name, content in members:
            archive.writestr(
                name,
                content,
            )

    return output.getvalue()


def _docx_bytes(document_xml: bytes) -> bytes:
    content_types = (
        b'<?xml version="1.0"?>'
        b'<Types '
        b'xmlns="http://schemas.openxmlformats.org/'
        b'package/2006/content-types"/>'
    )

    return _archive_bytes(
        [
            (
                "[Content_Types].xml",
                content_types,
            ),
            (
                "word/document.xml",
                document_xml,
            ),
        ]
    )


def _valid_document_xml(
    text: str = "ORKIO-PREMIUM-777",
) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<w:document xmlns:w="{WORD_NS}">'
        "<w:body><w:p><w:r><w:t>"
        + text
        + "</w:t></w:r></w:p></w:body>"
        "</w:document>"
    ).encode()


def test_default_policy_matches_settings_defaults():
    policy = default_document_ingestion_policy()

    fields = Settings.model_fields

    assert (
        fields[
            "document_ingestion_max_archive_entries"
        ].default
        == policy.archive.max_entries
    )

    assert (
        fields[
            "document_ingestion_max_total_uncompressed_bytes"
        ].default
        == policy.archive.max_total_uncompressed_bytes
    )

    assert (
        fields[
            "document_ingestion_max_member_bytes"
        ].default
        == policy.archive.max_member_uncompressed_bytes
    )

    assert (
        fields[
            "document_ingestion_docx_max_xml_bytes"
        ].default
        == policy.docx_max_xml_bytes
    )


def test_settings_reject_invalid_ingestion_relationship():
    with pytest.raises(
        ValidationError,
        match="DOCUMENT_INGESTION_LIMIT_RELATION_INVALID",
    ):
        Settings(
            _env_file=None,
            PLATFORM_ENVIRONMENT="test",
            PLATFORM_AUTH_MODE="test",
            PLATFORM_DOCUMENT_INGESTION_MAX_ARCHIVE_ENTRIES=10,
            PLATFORM_DOCUMENT_INGESTION_MAX_TOTAL_UNCOMPRESSED_BYTES=1000,
            PLATFORM_DOCUMENT_INGESTION_MAX_MEMBER_BYTES=900,
            PLATFORM_DOCUMENT_INGESTION_DOCX_MAX_XML_BYTES=901,
        )


def test_archive_entry_limit():
    raw = _archive_bytes(
        [
            (f"word/item-{index}.xml", b"x")
            for index in range(4)
        ]
    )

    limits = ArchiveSecurityLimits(
        max_entries=3,
        max_total_uncompressed_bytes=1000,
        max_member_uncompressed_bytes=1000,
    )

    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        with pytest.raises(
            ArchiveEntryLimitExceeded
        ):
            inspect_zip_archive(
                archive,
                limits=limits,
            )


def test_archive_total_uncompressed_limit():
    raw = _archive_bytes(
        [
            ("word/a.xml", b"A" * 600),
            ("word/b.xml", b"B" * 600),
        ]
    )

    limits = ArchiveSecurityLimits(
        max_entries=10,
        max_total_uncompressed_bytes=1000,
        max_member_uncompressed_bytes=1000,
    )

    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        with pytest.raises(
            ArchiveTotalSizeExceeded
        ):
            inspect_zip_archive(
                archive,
                limits=limits,
            )


def test_archive_member_limit():
    raw = _archive_bytes(
        [
            ("word/a.xml", b"A" * 1001),
        ]
    )

    limits = ArchiveSecurityLimits(
        max_entries=10,
        max_total_uncompressed_bytes=5000,
        max_member_uncompressed_bytes=1000,
    )

    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        with pytest.raises(
            ArchiveMemberTooLarge
        ):
            inspect_zip_archive(
                archive,
                limits=limits,
            )


def test_duplicate_archive_member_rejected():
    output = io.BytesIO()

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        with zipfile.ZipFile(
            output,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            archive.writestr(
                "word/document.xml",
                b"<a/>",
            )
            archive.writestr(
                "word/document.xml",
                b"<b/>",
            )

    limits = ArchiveSecurityLimits(
        max_entries=10,
        max_total_uncompressed_bytes=5000,
        max_member_uncompressed_bytes=5000,
    )

    with zipfile.ZipFile(
        io.BytesIO(output.getvalue())
    ) as archive:
        with pytest.raises(
            ArchiveDuplicateMember
        ):
            inspect_zip_archive(
                archive,
                limits=limits,
            )


def test_archive_traversal_member_rejected():
    raw = _archive_bytes(
        [
            ("../escape.xml", b"x"),
        ]
    )

    limits = ArchiveSecurityLimits(
        max_entries=10,
        max_total_uncompressed_bytes=5000,
        max_member_uncompressed_bytes=5000,
    )

    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        with pytest.raises(
            ArchivePathRejected
        ):
            inspect_zip_archive(
                archive,
                limits=limits,
            )


def test_high_compression_ratio_is_telemetry_not_blocker():
    raw = _archive_bytes(
        [
            (
                "word/document.xml",
                b"A" * 500_000,
            ),
        ]
    )

    limits = ArchiveSecurityLimits(
        max_entries=10,
        max_total_uncompressed_bytes=1_000_000,
        max_member_uncompressed_bytes=1_000_000,
    )

    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        result = inspect_zip_archive(
            archive,
            limits=limits,
        )

    assert (
        result.maximum_compression_ratio
        > 100
    )


def test_bounded_member_read():
    raw = _archive_bytes(
        [
            (
                "word/document.xml",
                b"A" * 501,
            ),
        ]
    )

    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        with pytest.raises(
            ArchiveMemberTooLarge
        ):
            read_zip_member_bounded(
                archive,
                "word/document.xml",
                max_bytes=500,
            )


def test_untrusted_xml_rejects_dtd_and_entity():
    xml = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE root ['
        b'<!ENTITY orkio "ORKIO_ENTITY_EXPANDED">'
        b']>'
        b'<root>&orkio;</root>'
    )

    with pytest.raises(
        UnsafeXmlRejected
    ):
        parse_untrusted_xml(xml)


def test_valid_untrusted_xml_parses():
    root = parse_untrusted_xml(
        b"<root><value>777</value></root>"
    )

    assert root.tag == "root"


def test_document_context_docx_still_extracts():
    raw = _docx_bytes(
        _valid_document_xml()
    )

    result = extract_document_text(
        filename="premium.docx",
        mime_type=DOCX_MIME,
        raw=raw,
        max_chars=1000,
        max_pdf_pages=10,
    )

    assert result == "ORKIO-PREMIUM-777"


def test_document_context_rejects_unsafe_docx():
    xml = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE w:document ['
        b'<!ENTITY orkio "ORKIO_ENTITY_EXPANDED">'
        b']>'
        b'<w:document '
        b'xmlns:w="http://schemas.openxmlformats.org/'
        b'wordprocessingml/2006/main">'
        b'<w:body><w:p><w:r><w:t>'
        b'&orkio;'
        b'</w:t></w:r></w:p></w:body>'
        b'</w:document>'
    )

    with pytest.raises(
        DocumentExtractionFailed,
        match="DOCUMENT_DOCX_XML_UNSAFE",
    ):
        extract_document_text(
            filename="unsafe.docx",
            mime_type=DOCX_MIME,
            raw=_docx_bytes(xml),
            max_chars=1000,
            max_pdf_pages=10,
        )


def test_document_context_honours_custom_xml_budget():
    policy = DocumentIngestionSecurityPolicy(
        archive=ArchiveSecurityLimits(
            max_entries=20,
            max_total_uncompressed_bytes=10_000,
            max_member_uncompressed_bytes=10_000,
        ),
        docx_max_xml_bytes=256,
    )

    xml = _valid_document_xml(
        "A" * 1000
    )

    with pytest.raises(
        DocumentIntegrityError,
        match="DOCUMENT_DOCX_XML_TOO_LARGE",
    ):
        extract_document_text(
            filename="oversized.docx",
            mime_type=DOCX_MIME,
            raw=_docx_bytes(xml),
            max_chars=1000,
            max_pdf_pages=10,
            ingestion_policy=policy,
        )


def test_security_error_details_are_safe():
    policy = DocumentIngestionSecurityPolicy(
        archive=ArchiveSecurityLimits(
            max_entries=20,
            max_total_uncompressed_bytes=10_000,
            max_member_uncompressed_bytes=10_000,
        ),
        docx_max_xml_bytes=256,
    )

    xml = _valid_document_xml(
        "SENSITIVE-CONTENT-" * 100
    )

    caught: DocumentContextError | None = None

    try:
        extract_document_text(
            filename="safe-log.docx",
            mime_type=DOCX_MIME,
            raw=_docx_bytes(xml),
            max_chars=1000,
            max_pdf_pages=10,
            ingestion_policy=policy,
        )
    except DocumentContextError as exc:
        caught = exc

    assert caught is not None

    details = _security_error_details(
        caught
    )

    assert (
        details["ingestion_security_event"]
        == "document_ingestion_rejected"
    )

    serialised = repr(details)

    assert "SENSITIVE-CONTENT" not in serialised
    assert "safe-log.docx" not in serialised
