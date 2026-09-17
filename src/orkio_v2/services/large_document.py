from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import codecs
import hashlib
import html
import io
import json
import logging
from pathlib import Path, PurePosixPath
import re
import tempfile
import uuid
import zipfile
import xml.etree.ElementTree as ET

from fastapi import UploadFile
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..auth import Principal
from ..models import (
    KnowledgeDocument,
    KnowledgeDocumentChunk,
    KnowledgeDocumentDerivative,
    KnowledgeDocumentSection,
    KnowledgeDocumentSelection,
    KnowledgeScope,
    KnowledgeStatus,
)
from .blob_storage import BlobStorage, BlobStorageError
from .knowledge_repository import get_managed_document


logger = logging.getLogger("patroai.knowledge.large_document")

CANONICAL_KIND = "CANONICAL_MARKDOWN"
EXTRACTOR_NAME = "patroai-deterministic"
EXTRACTOR_VERSION = "1"
_WORD_RE = re.compile(r"[A-Za-zÀ-ÖØ-öø-ÿ0-9_]{2,}", re.UNICODE)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_PAGE_HEADING_RE = re.compile(r"^Página\s+(\d+)$", re.IGNORECASE)

_ALLOWED_TEXT_MIME = {
    "text/plain",
    "text/csv",
    "text/markdown",
    "application/json",
}
PDF_MIME = "application/pdf"
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
PPTX_MIME = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


class LargeDocumentError(RuntimeError):
    def __init__(self, code: str, status_code: int = 409):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class StagedUpload:
    path: Path
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class CanonicalizationResult:
    path: Path
    source_chars: int
    canonical_chars: int
    page_count: int | None
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StructureSection:
    id: str
    ordinal: int
    heading: str
    level: int
    page_start: int | None
    page_end: int | None
    byte_start: int
    byte_end: int
    estimated_tokens: int
    parent_id: str | None


@dataclass(frozen=True, slots=True)
class StructureChunk:
    id: str
    ordinal: int
    section_id: str | None
    byte_start: int
    byte_end: int
    estimated_tokens: int
    text_sha256: str
    terms: tuple[str, ...]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sanitize_filename(filename: str | None) -> str:
    safe = PurePosixPath((filename or "file").replace("\\", "/")).name
    if not safe or safe in {".", ".."}:
        raise LargeDocumentError("FILENAME_INVALID", 400)
    return safe[:255]


def _staging_root(settings) -> Path:
    if str(getattr(settings, "artifact_storage_backend", "local")).lower() == "local":
        root = Path(settings.artifact_storage_path).resolve() / ".ingest"
    else:
        root = Path(tempfile.gettempdir()) / "patroai-knowledge-ingest"
    root.mkdir(parents=True, exist_ok=True)
    return root


async def stage_upload(
    file: UploadFile,
    *,
    settings,
    max_bytes: int,
    chunk_bytes: int = 1024 * 1024,
) -> StagedUpload:
    """Stream an UploadFile to disk with bounded memory and incremental SHA-256."""
    if max_bytes <= 0:
        raise LargeDocumentError("FILE_SIZE_LIMIT_INVALID", 500)
    path = _staging_root(settings) / f"{uuid.uuid4()}.uploading"
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("xb") as target:
            while True:
                chunk = await file.read(chunk_bytes)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise LargeDocumentError("FILE_TOO_LARGE", 413)
                digest.update(chunk)
                target.write(chunk)
        return StagedUpload(path=path, size_bytes=total, sha256=digest.hexdigest())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        try:
            await file.close()
        except Exception:
            pass


def cleanup_staged_upload(staged: StagedUpload | None) -> None:
    if staged is not None:
        staged.path.unlink(missing_ok=True)


class _CanonicalWriter:
    def __init__(self, path: Path):
        self.path = path
        self.file = path.open("wb")
        self.chars = 0

    def write(self, value: str) -> None:
        if not value:
            return
        encoded = value.encode("utf-8", errors="replace")
        self.file.write(encoded)
        self.chars += len(value)

    def line(self, value: str = "") -> None:
        self.write(value.rstrip() + "\n")

    def close(self) -> None:
        self.file.close()


def _write_text_source(source: Path, writer: _CanonicalWriter, *, mime_type: str) -> int:
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    chars = 0
    with source.open("rb") as raw:
        while True:
            chunk = raw.read(1024 * 1024)
            if not chunk:
                break
            text = decoder.decode(chunk)
            chars += len(text)
            writer.write(text)
        tail = decoder.decode(b"", final=True)
        chars += len(tail)
        writer.write(tail)
    if writer.chars and not _ends_with_newline(writer.path):
        writer.line()
    return chars


def _ends_with_newline(path: Path) -> bool:
    if not path.exists() or path.stat().st_size == 0:
        return True
    with path.open("rb") as handle:
        handle.seek(-1, io.SEEK_END)
        return handle.read(1) == b"\n"


def _xml_text_stream(member) -> str:
    parts: list[str] = []
    for event, elem in ET.iterparse(member, events=("end",)):
        tag = elem.tag.rsplit("}", 1)[-1]
        if tag in {"t", "v"} and elem.text:
            parts.append(elem.text)
        elif tag in {"p", "tr", "row"}:
            parts.append("\n")
        elif tag in {"tab"}:
            parts.append("\t")
        elem.clear()
    return "".join(parts)


def _write_docx(source: Path, writer: _CanonicalWriter) -> int:
    writer.line("# Documento")
    source_chars = 0
    with zipfile.ZipFile(source) as archive:
        try:
            with archive.open("word/document.xml") as member:
                text = _xml_text_stream(member)
        except KeyError as exc:
            raise LargeDocumentError("DOCUMENT_DOCX_STRUCTURE_INVALID", 422) from exc
    for paragraph in text.splitlines():
        clean = paragraph.strip()
        if clean:
            writer.line(clean)
            source_chars += len(clean)
    return source_chars


def _slide_sort_key(name: str) -> tuple[int, str]:
    match = re.search(r"slide(\d+)\.xml$", name)
    return (int(match.group(1)) if match else 10**9, name)


def _write_pptx(source: Path, writer: _CanonicalWriter) -> int:
    source_chars = 0
    with zipfile.ZipFile(source) as archive:
        slide_names = sorted(
            [
                name
                for name in archive.namelist()
                if re.fullmatch(r"ppt/slides/slide\d+\.xml", name)
            ],
            key=_slide_sort_key,
        )
        for index, name in enumerate(slide_names, start=1):
            writer.line(f"## Slide {index}")
            with archive.open(name) as member:
                text = _xml_text_stream(member)
            for line in text.splitlines():
                clean = line.strip()
                if clean:
                    writer.line(clean)
                    source_chars += len(clean)
            writer.line()
    return source_chars


def _write_xlsx(source: Path, writer: _CanonicalWriter) -> int:
    try:
        import openpyxl
    except ImportError as exc:
        raise LargeDocumentError("DOCUMENT_XLSX_READER_UNAVAILABLE", 503) from exc
    source_chars = 0
    workbook = openpyxl.load_workbook(source, read_only=True, data_only=True)
    try:
        for sheet in workbook.worksheets:
            writer.line(f"## {sheet.title}")
            for row in sheet.iter_rows(values_only=True):
                cells = ["" if value is None else str(value) for value in row]
                line = " | ".join(cells).rstrip()
                if line.strip(" |"):
                    writer.line(line)
                    source_chars += len(line)
            writer.line()
    finally:
        workbook.close()
    return source_chars


def _write_pdf(source: Path, writer: _CanonicalWriter, *, max_pages: int) -> tuple[int, int, tuple[str, ...]]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise LargeDocumentError("DOCUMENT_PDF_READER_UNAVAILABLE", 503) from exc
    try:
        reader = PdfReader(str(source), strict=True)
    except Exception as exc:
        raise LargeDocumentError("DOCUMENT_PDF_EXTRACTION_FAILED", 422) from exc
    page_count = len(reader.pages)
    warnings: list[str] = []
    if page_count > max_pages:
        raise LargeDocumentError("DOCUMENT_PDF_PAGE_LIMIT_EXCEEDED", 413)
    source_chars = 0
    for index, page in enumerate(reader.pages, start=1):
        writer.line(f"## Página {index}")
        try:
            text = page.extract_text() or ""
        except Exception as exc:
            warnings.append(f"PDF_PAGE_{index}_EXTRACTION_FAILED")
            logger.warning("KNOWLEDGE_PDF_PAGE_EXTRACTION_FAILED page=%s", index)
            continue
        clean = text.replace("\x00", "").strip()
        if clean:
            writer.line(clean)
            source_chars += len(clean)
        writer.line()
    if page_count and source_chars == 0:
        raise LargeDocumentError("DOCUMENT_OCR_REQUIRED", 422)
    return source_chars, page_count, tuple(warnings)


def canonicalize_source(
    source: Path,
    *,
    mime_type: str,
    filename: str,
    settings,
) -> CanonicalizationResult:
    """Convert a source file into deterministic UTF-8 Markdown using bounded reads."""
    destination = source.with_name(f"{source.name}.canonical.md")
    destination.unlink(missing_ok=True)
    writer = _CanonicalWriter(destination)
    warnings: tuple[str, ...] = ()
    page_count: int | None = None
    try:
        writer.line(f"# {sanitize_filename(filename)}")
        writer.line()
        if mime_type in _ALLOWED_TEXT_MIME:
            source_chars = _write_text_source(source, writer, mime_type=mime_type)
        elif mime_type == PDF_MIME:
            source_chars, page_count, warnings = _write_pdf(
                source,
                writer,
                max_pages=int(settings.knowledge_large_document_max_pdf_pages),
            )
        elif mime_type == DOCX_MIME:
            source_chars = _write_docx(source, writer)
        elif mime_type == PPTX_MIME:
            source_chars = _write_pptx(source, writer)
        elif mime_type == XLSX_MIME:
            source_chars = _write_xlsx(source, writer)
        else:
            raise LargeDocumentError("DOCUMENT_EXTRACTION_UNSUPPORTED", 415)
    finally:
        writer.close()
    return CanonicalizationResult(
        path=destination,
        source_chars=source_chars,
        canonical_chars=writer.chars,
        page_count=page_count,
        warnings=warnings,
    )


def hash_file(path: Path, chunk_bytes: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(chunk_bytes)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _token_estimate(text: str) -> int:
    return max(1, (len(text) + 3) // 4) if text else 0


def _terms(text: str, limit: int = 64) -> tuple[str, ...]:
    counts: dict[str, int] = {}
    for raw in _WORD_RE.findall(text.lower()):
        if len(raw) < 3:
            continue
        counts[raw] = counts.get(raw, 0) + 1
    ranked = sorted(counts, key=lambda item: (-counts[item], item))
    return tuple(ranked[:limit])


def build_structure(
    canonical_path: Path,
    *,
    chunk_target_chars: int,
    chunk_overlap_chars: int,
) -> tuple[list[StructureSection], list[StructureChunk]]:
    """Create a structural index using bounded reads.

    Offsets are UTF-8 byte offsets so retrieval can use local seek or S3 Range
    without loading the canonical document into memory.
    """
    headings: list[tuple[int, str, int, int | None]] = []
    byte_offset = 0
    with canonical_path.open("rb") as source:
        while True:
            line = source.readline()
            if not line:
                break
            decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
            heading_match = _HEADING_RE.match(decoded)
            if heading_match:
                heading = heading_match.group(2).strip()
                level = len(heading_match.group(1))
                page_match = _PAGE_HEADING_RE.match(heading)
                page = int(page_match.group(1)) if page_match else None
                headings.append((byte_offset, heading, level, page))
            byte_offset += len(line)
    raw_len = byte_offset
    if not headings:
        headings = [(0, "Documento", 0, None)]

    sections: list[StructureSection] = []
    parent_stack: list[tuple[int, str]] = []
    for ordinal, (byte_start, heading, level, page) in enumerate(headings):
        byte_end = headings[ordinal + 1][0] if ordinal + 1 < len(headings) else raw_len
        while parent_stack and parent_stack[-1][0] >= level:
            parent_stack.pop()
        parent_id = parent_stack[-1][1] if parent_stack and level > 0 else None
        section_id = str(uuid.uuid4())
        next_page = None
        if page is not None:
            for future in headings[ordinal + 1:]:
                if future[3] is not None:
                    next_page = future[3] - 1
                    break
        sections.append(
            StructureSection(
                id=section_id,
                ordinal=ordinal,
                heading=heading[:500],
                level=level,
                page_start=page,
                page_end=next_page,
                byte_start=byte_start,
                byte_end=byte_end,
                estimated_tokens=max(0, (byte_end - byte_start + 3) // 4),
                parent_id=parent_id,
            )
        )
        if level > 0:
            parent_stack.append((level, section_id))

    chunks: list[StructureChunk] = []
    ordinal = 0
    target_bytes = max(1_000, int(chunk_target_chars))
    overlap_bytes = max(0, min(int(chunk_overlap_chars), target_bytes - 1))
    with canonical_path.open("rb") as source:
        for section in sections:
            cursor = section.byte_start
            while cursor < section.byte_end:
                length = min(target_bytes, section.byte_end - cursor)
                source.seek(cursor)
                block = source.read(length)
                if not block:
                    break
                next_end = cursor + len(block)
                if next_end < section.byte_end:
                    split = max(block.rfind(b"\n\n"), block.rfind(b"\n"))
                    if split > len(block) // 2:
                        block = block[: split + 1]
                        next_end = cursor + len(block)
                text = block.decode("utf-8", errors="replace").strip()
                if text:
                    chunks.append(
                        StructureChunk(
                            id=str(uuid.uuid4()),
                            ordinal=ordinal,
                            section_id=section.id,
                            byte_start=cursor,
                            byte_end=next_end,
                            estimated_tokens=_token_estimate(text),
                            text_sha256=hashlib.sha256(block).hexdigest(),
                            terms=_terms(section.heading + "\n" + text),
                        )
                    )
                    ordinal += 1
                if next_end >= section.byte_end:
                    break
                cursor = max(cursor + 1, next_end - overlap_bytes)
    return sections, chunks


def _canonical_storage_key(document: KnowledgeDocument) -> str:
    namespace = document.tenant_id or "global"
    return (
        f"knowledge/derived/{document.scope.lower()}/{namespace}/"
        f"{document.logical_document_id}/v{document.version}/canonical-v1.md"
    )


def ensure_pending_derivative(db: Session, *, document: KnowledgeDocument) -> KnowledgeDocumentDerivative:
    derivative = db.scalar(
        select(KnowledgeDocumentDerivative).where(
            KnowledgeDocumentDerivative.knowledge_id == document.id,
            KnowledgeDocumentDerivative.kind == CANONICAL_KIND,
        )
    )
    if derivative is not None:
        return derivative
    derivative = KnowledgeDocumentDerivative(
        id=str(uuid.uuid4()),
        knowledge_id=document.id,
        tenant_id=document.tenant_id,
        kind=CANONICAL_KIND,
        storage_key=None,
        sha256=None,
        size_bytes=None,
        status="PENDING",
        extractor=EXTRACTOR_NAME,
        extractor_version=EXTRACTOR_VERSION,
        source_chars=None,
        canonical_chars=None,
        page_count=None,
        warnings_json=[],
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(derivative)
    db.commit()
    return derivative


def derivative_payload(derivative: KnowledgeDocumentDerivative | None) -> dict[str, object] | None:
    if derivative is None:
        return None
    return {
        "id": derivative.id,
        "kind": derivative.kind,
        "status": derivative.status,
        "size_bytes": derivative.size_bytes,
        "sha256": derivative.sha256,
        "source_chars": derivative.source_chars,
        "canonical_chars": derivative.canonical_chars,
        "page_count": derivative.page_count,
        "warnings": list(derivative.warnings_json or []),
        "extractor": derivative.extractor,
        "extractor_version": derivative.extractor_version,
        "updated_at": derivative.updated_at,
    }


def process_document(
    db: Session,
    *,
    document: KnowledgeDocument,
    storage: BlobStorage,
    settings,
) -> KnowledgeDocumentDerivative:
    derivative = ensure_pending_derivative(db, document=document)
    derivative.status = "PROCESSING"
    derivative.updated_at = utcnow()
    db.commit()

    process_root = _staging_root(settings)
    source = process_root / f"{document.id}.source"
    canonical: CanonicalizationResult | None = None
    new_storage_key: str | None = None
    try:
        storage.materialize(document.storage_key, source)
        if hash_file(source) != document.sha256:
            raise LargeDocumentError("KNOWLEDGE_SHA256_MISMATCH", 409)
        canonical = canonicalize_source(
            source,
            mime_type=document.mime_type,
            filename=document.source_filename,
            settings=settings,
        )
        canonical_digest = hash_file(canonical.path)
        new_storage_key = _canonical_storage_key(document)

        existing_key = derivative.storage_key
        if existing_key and existing_key != new_storage_key:
            try:
                storage.delete(existing_key)
            except BlobStorageError:
                logger.warning("KNOWLEDGE_CANONICAL_OLD_BLOB_DELETE_FAILED knowledge_id=%s", document.id)

        created = storage.put_file_if_absent(
            new_storage_key,
            canonical.path,
            content_type="text/markdown; charset=utf-8",
        )
        if not created:
            verify_path = canonical.path.with_name(canonical.path.name + ".existing")
            try:
                storage.materialize(new_storage_key, verify_path)
                if hash_file(verify_path) != canonical_digest:
                    raise LargeDocumentError("KNOWLEDGE_CANONICAL_STORAGE_CONFLICT", 409)
            finally:
                verify_path.unlink(missing_ok=True)

        sections, chunks = build_structure(
            canonical.path,
            chunk_target_chars=int(settings.knowledge_chunk_target_chars),
            chunk_overlap_chars=int(settings.knowledge_chunk_overlap_chars),
        )

        db.execute(
            delete(KnowledgeDocumentChunk).where(
                KnowledgeDocumentChunk.knowledge_id == document.id
            )
        )
        db.execute(
            delete(KnowledgeDocumentSection).where(
                KnowledgeDocumentSection.knowledge_id == document.id
            )
        )

        derivative.storage_key = new_storage_key
        derivative.sha256 = canonical_digest
        derivative.size_bytes = canonical.path.stat().st_size
        derivative.status = "PARTIAL" if canonical.warnings else "READY"
        derivative.extractor = EXTRACTOR_NAME
        derivative.extractor_version = EXTRACTOR_VERSION
        derivative.source_chars = canonical.source_chars
        derivative.canonical_chars = canonical.canonical_chars
        derivative.page_count = canonical.page_count
        derivative.warnings_json = list(canonical.warnings)
        derivative.updated_at = utcnow()

        for section in sections:
            db.add(
                KnowledgeDocumentSection(
                    id=section.id,
                    knowledge_id=document.id,
                    derivative_id=derivative.id,
                    tenant_id=document.tenant_id,
                    parent_section_id=section.parent_id,
                    ordinal=section.ordinal,
                    heading=section.heading,
                    level=section.level,
                    page_start=section.page_start,
                    page_end=section.page_end,
                    byte_start=section.byte_start,
                    byte_end=section.byte_end,
                    estimated_tokens=section.estimated_tokens,
                    created_at=utcnow(),
                )
            )
        for chunk in chunks:
            db.add(
                KnowledgeDocumentChunk(
                    id=chunk.id,
                    knowledge_id=document.id,
                    derivative_id=derivative.id,
                    section_id=chunk.section_id,
                    tenant_id=document.tenant_id,
                    ordinal=chunk.ordinal,
                    byte_start=chunk.byte_start,
                    byte_end=chunk.byte_end,
                    estimated_tokens=chunk.estimated_tokens,
                    text_sha256=chunk.text_sha256,
                    terms_json=list(chunk.terms),
                    created_at=utcnow(),
                )
            )
        db.commit()
        logger.info(
            "KNOWLEDGE_CANONICAL_READY knowledge_id=%s source_bytes=%s canonical_bytes=%s "
            "source_chars=%s canonical_chars=%s sections=%s chunks=%s status=%s",
            document.id,
            document.size_bytes,
            derivative.size_bytes,
            derivative.source_chars,
            derivative.canonical_chars,
            len(sections),
            len(chunks),
            derivative.status,
        )
        return derivative
    except LargeDocumentError as exc:
        db.rollback()
        derivative = db.get(KnowledgeDocumentDerivative, derivative.id) or derivative
        derivative.status = "OCR_REQUIRED" if exc.code == "DOCUMENT_OCR_REQUIRED" else "FAILED"
        derivative.warnings_json = [exc.code]
        derivative.updated_at = utcnow()
        db.add(derivative)
        db.commit()
        raise
    except Exception as exc:
        db.rollback()
        derivative = db.get(KnowledgeDocumentDerivative, derivative.id) or derivative
        derivative.status = "FAILED"
        derivative.warnings_json = ["KNOWLEDGE_CANONICALIZATION_FAILED"]
        derivative.updated_at = utcnow()
        db.add(derivative)
        db.commit()
        raise LargeDocumentError("KNOWLEDGE_CANONICALIZATION_FAILED", 500) from exc
    finally:
        source.unlink(missing_ok=True)
        if canonical is not None:
            canonical.path.unlink(missing_ok=True)


def get_derivative(db: Session, *, knowledge_id: str) -> KnowledgeDocumentDerivative | None:
    return db.scalar(
        select(KnowledgeDocumentDerivative).where(
            KnowledgeDocumentDerivative.knowledge_id == knowledge_id,
            KnowledgeDocumentDerivative.kind == CANONICAL_KIND,
        )
    )


def structure_payload(db: Session, *, document: KnowledgeDocument) -> dict[str, object]:
    derivative = get_derivative(db, knowledge_id=document.id)
    sections = list(
        db.scalars(
            select(KnowledgeDocumentSection)
            .where(KnowledgeDocumentSection.knowledge_id == document.id)
            .order_by(KnowledgeDocumentSection.ordinal.asc())
        ).all()
    )
    chunks = list(
        db.scalars(
            select(KnowledgeDocumentChunk)
            .where(KnowledgeDocumentChunk.knowledge_id == document.id)
            .order_by(KnowledgeDocumentChunk.ordinal.asc())
        ).all()
    )
    return {
        "knowledge_id": document.id,
        "logical_document_id": document.logical_document_id,
        "title": document.title,
        "filename": document.source_filename,
        "derivative": derivative_payload(derivative),
        "sections": [
            {
                "id": row.id,
                "parent_section_id": row.parent_section_id,
                "ordinal": row.ordinal,
                "heading": row.heading,
                "level": row.level,
                "page_start": row.page_start,
                "page_end": row.page_end,
                "estimated_tokens": row.estimated_tokens,
                "chunk_count": sum(1 for chunk in chunks if chunk.section_id == row.id),
            }
            for row in sections
        ],
        "chunk_count": len(chunks),
    }


def save_selection(
    db: Session,
    *,
    document: KnowledgeDocument,
    principal: Principal,
    mode: str,
    section_ids: list[str],
) -> KnowledgeDocumentSelection:
    mode = str(mode or "").strip().upper()
    if mode not in {"MANUAL", "AUTO"}:
        raise LargeDocumentError("KNOWLEDGE_SELECTION_MODE_INVALID", 422)
    known = {
        row.id
        for row in db.scalars(
            select(KnowledgeDocumentSection).where(
                KnowledgeDocumentSection.knowledge_id == document.id
            )
        ).all()
    }
    requested = [str(item) for item in section_ids if str(item)]
    if any(item not in known for item in requested):
        raise LargeDocumentError("KNOWLEDGE_SELECTION_SECTION_INVALID", 422)
    selection = db.scalar(
        select(KnowledgeDocumentSelection).where(
            KnowledgeDocumentSelection.knowledge_id == document.id,
            KnowledgeDocumentSelection.tenant_id == principal.tenant_id,
            KnowledgeDocumentSelection.user_id == principal.user_id,
        )
    )
    if selection is None:
        selection = KnowledgeDocumentSelection(
            id=str(uuid.uuid4()),
            knowledge_id=document.id,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            mode=mode,
            section_ids=requested,
            updated_at=utcnow(),
        )
        db.add(selection)
    else:
        selection.mode = mode
        selection.section_ids = requested
        selection.updated_at = utcnow()
    db.commit()
    return selection


def selection_payload(selection: KnowledgeDocumentSelection | None) -> dict[str, object]:
    if selection is None:
        return {"mode": "AUTO", "section_ids": []}
    return {
        "mode": selection.mode,
        "section_ids": list(selection.section_ids or []),
        "updated_at": selection.updated_at,
    }


def get_selection(
    db: Session,
    *,
    knowledge_id: str,
    tenant_id: str,
    user_id: str,
) -> KnowledgeDocumentSelection | None:
    return db.scalar(
        select(KnowledgeDocumentSelection).where(
            KnowledgeDocumentSelection.knowledge_id == knowledge_id,
            KnowledgeDocumentSelection.tenant_id == tenant_id,
            KnowledgeDocumentSelection.user_id == user_id,
        )
    )


def managed_document_for_processing(
    db: Session,
    *,
    document_id: str,
    principal: Principal,
) -> KnowledgeDocument:
    return get_managed_document(
        db,
        document_id=document_id,
        principal=principal,
    )


def visible_document_for_navigator(
    db: Session,
    *,
    document_id: str,
    principal: Principal,
) -> KnowledgeDocument:
    """Return only knowledge the actor could legitimately consume."""
    document = db.get(KnowledgeDocument, document_id)
    if document is None or document.status not in {
        KnowledgeStatus.active.value,
        KnowledgeStatus.draft.value,
    }:
        raise LargeDocumentError("KNOWLEDGE_NOT_FOUND", 404)
    if document.scope == KnowledgeScope.personal.value:
        if (
            document.tenant_id != principal.tenant_id
            or document.owner_user_id != principal.user_id
        ):
            raise LargeDocumentError("KNOWLEDGE_NOT_FOUND", 404)
        return document
    if document.scope == KnowledgeScope.institutional.value:
        if document.tenant_id != principal.tenant_id:
            raise LargeDocumentError("KNOWLEDGE_NOT_FOUND", 404)
        # Draft institutional content remains management-only.
        if document.status == KnowledgeStatus.draft.value:
            return get_managed_document(
                db, document_id=document_id, principal=principal
            )
        return document
    if document.scope == KnowledgeScope.platform.value:
        if document.tenant_id is not None:
            raise LargeDocumentError("KNOWLEDGE_NOT_FOUND", 404)
        if document.status == KnowledgeStatus.draft.value:
            return get_managed_document(
                db, document_id=document_id, principal=principal
            )
        return document
    raise LargeDocumentError("KNOWLEDGE_NOT_FOUND", 404)


def lexical_query_terms(query: str) -> set[str]:
    return set(_terms(query, limit=48))


def ranked_chunks(
    chunks: list[KnowledgeDocumentChunk],
    *,
    query: str,
    selected_section_ids: set[str] | None,
    top_k: int,
) -> list[KnowledgeDocumentChunk]:
    if selected_section_ids:
        return [
            chunk
            for chunk in sorted(chunks, key=lambda row: row.ordinal)
            if chunk.section_id in selected_section_ids
        ]
    query_terms = lexical_query_terms(query)
    if not query_terms:
        return sorted(chunks, key=lambda row: row.ordinal)[:top_k]
    scored: list[tuple[int, int, KnowledgeDocumentChunk]] = []
    for chunk in chunks:
        terms = set(str(item) for item in (chunk.terms_json or []))
        score = len(query_terms & terms)
        if score:
            scored.append((score, -chunk.ordinal, chunk))
    if not scored:
        return sorted(chunks, key=lambda row: row.ordinal)[:top_k]
    return [
        item[2]
        for item in sorted(scored, key=lambda value: (-value[0], -value[1]))[:top_k]
    ]


def canonical_context_for_document(
    db: Session,
    *,
    storage: BlobStorage,
    document: KnowledgeDocument,
    tenant_id: str,
    user_id: str,
    query: str,
    max_chars: int,
    top_k: int,
) -> tuple[str, int, bool] | None:
    derivative = get_derivative(db, knowledge_id=document.id)
    if derivative is None or derivative.status not in {"READY", "PARTIAL"} or not derivative.storage_key:
        return None
    chunks = list(
        db.scalars(
            select(KnowledgeDocumentChunk)
            .where(KnowledgeDocumentChunk.knowledge_id == document.id)
            .order_by(KnowledgeDocumentChunk.ordinal.asc())
        ).all()
    )
    if not chunks:
        return None
    selection = get_selection(
        db,
        knowledge_id=document.id,
        tenant_id=tenant_id,
        user_id=user_id,
    )
    selected_ids: set[str] | None = None
    if selection is not None and selection.mode == "MANUAL" and selection.section_ids:
        selected_ids = set(str(item) for item in selection.section_ids)

    ranked = ranked_chunks(
        chunks,
        query=query,
        selected_section_ids=selected_ids,
        top_k=max(1, top_k),
    )
    pieces: list[str] = []
    provided = 0
    truncated = False
    seen_ranges: set[tuple[int, int]] = set()
    for chunk in ranked:
        if provided >= max_chars:
            truncated = True
            break
        range_key = (chunk.byte_start, chunk.byte_end)
        if range_key in seen_ranges:
            continue
        seen_ranges.add(range_key)
        raw = storage.read_range(
            derivative.storage_key,
            chunk.byte_start,
            chunk.byte_end,
        )
        if hashlib.sha256(raw).hexdigest() != chunk.text_sha256:
            raise LargeDocumentError("KNOWLEDGE_CANONICAL_CHUNK_SHA256_MISMATCH", 409)
        text = raw.decode("utf-8", errors="replace").strip()
        remaining = max_chars - provided
        if len(text) > remaining:
            text = text[:remaining].rstrip()
            truncated = True
        if text:
            pieces.append(text)
            provided += len(text)
    if len(ranked) < len(chunks):
        truncated = True
    if not pieces:
        return None
    return "\n\n".join(pieces), provided, truncated
