from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator, Protocol

from .audit_path_policy import AuditPathPolicy, AuditPathPolicyError, VerifiedFile


class AuditArchiveSourceError(RuntimeError):
    code = "AUDIT_ARCHIVE_SOURCE_ERROR"


@dataclass(frozen=True, slots=True)
class AuditArtifactRecord:
    artifact_id: str
    tenant_id: str
    storage_key: str
    sha256: str


class ArtifactLookup(Protocol):
    def get(self, artifact_id: str) -> AuditArtifactRecord | None: ...


class SqlAlchemyArtifactLookup:
    """Server-side adapter over the platform Artifact table.

    Tenant authorization is intentionally performed by AuditArchiveSourceResolver,
    not by any client-provided field.
    """

    def __init__(self, db) -> None:
        self._db = db

    def get(self, artifact_id: str) -> AuditArtifactRecord | None:
        from ..models import Artifact

        row = self._db.get(Artifact, artifact_id)
        if row is None:
            return None
        return AuditArtifactRecord(
            artifact_id=str(row.id),
            tenant_id=str(row.tenant_id),
            storage_key=str(row.storage_key),
            sha256=str(row.sha256),
        )


def _safe_storage_key(storage_key: str, *, tenant_id: str) -> str:
    if not storage_key or "\\" in storage_key or "\x00" in storage_key:
        raise AuditArchiveSourceError("AUDIT_ARCHIVE_SOURCE_NOT_ALLOWED")
    pure = PurePosixPath(storage_key)
    parts = pure.parts
    if (
        pure.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or not tenant_id
        or parts[0] != tenant_id
    ):
        raise AuditArchiveSourceError("AUDIT_ARCHIVE_SOURCE_NOT_ALLOWED")
    return pure.as_posix()


def _sha256_verified_file(verified: VerifiedFile) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < verified.size:
        chunk = os.pread(
            verified.fd,
            min(64 * 1024, verified.size - offset),
            offset,
        )
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    if offset != verified.size:
        raise AuditArchiveSourceError("AUDIT_ARCHIVE_SOURCE_SHORT_READ")
    return digest.hexdigest()


class AuditArchiveSourceResolver:
    """Resolve caller-safe archive references into the canonical VerifiedFile.

    The artifact branch is local-storage-only in Gate 033A. Remote object-store
    retrieval is intentionally not introduced here because the audit capability
    remains network=false and no operational invocation path is enabled.
    """

    def __init__(
        self,
        *,
        path_policy: AuditPathPolicy,
        artifact_lookup: ArtifactLookup,
        artifact_storage_root_id: str = "artifact-storage",
    ) -> None:
        self._path_policy = path_policy
        self._artifact_lookup = artifact_lookup
        self._artifact_storage_root_id = artifact_storage_root_id

    @classmethod
    def from_local_runtime(cls, *, db, settings, local_roots=None):
        backend = str(
            getattr(settings, "artifact_storage_backend", "local") or "local"
        ).lower()
        if backend != "local":
            raise AuditArchiveSourceError("AUDIT_ARCHIVE_SOURCE_NOT_ALLOWED")

        configured = Path(str(settings.artifact_storage_path))
        storage_root = configured if configured.is_absolute() else Path.cwd() / configured
        roots = dict(local_roots or {})
        roots["artifact-storage"] = storage_root
        return cls(
            path_policy=AuditPathPolicy(roots),
            artifact_lookup=SqlAlchemyArtifactLookup(db),
        )

    @contextmanager
    def resolve_artifact(
        self,
        *,
        artifact_id: str,
        tenant_id: str,
    ) -> Iterator[VerifiedFile]:
        record = self._artifact_lookup.get(artifact_id)
        if record is None:
            raise AuditArchiveSourceError("AUDIT_ARCHIVE_NOT_FOUND")
        if record.tenant_id != tenant_id:
            raise AuditArchiveSourceError(
                "AUDIT_ARCHIVE_ARTIFACT_TENANT_MISMATCH"
            )

        storage_key = _safe_storage_key(record.storage_key, tenant_id=tenant_id)
        try:
            with self._path_policy.open_verified_file(
                root_id=self._artifact_storage_root_id,
                relative_path=storage_key,
            ) as verified:
                actual_sha256 = _sha256_verified_file(verified)
                expected_sha256 = record.sha256.strip().lower()
                if (
                    len(expected_sha256) != 64
                    or actual_sha256 != expected_sha256
                ):
                    raise AuditArchiveSourceError(
                        "AUDIT_ARCHIVE_SOURCE_INTEGRITY_MISMATCH"
                    )

                # Do not expose the physical storage key downstream. The adapter
                # receives the same identity-bound fd with a sanitized logical
                # reference suitable for evidence.
                verified.root_id = "artifact"
                verified.relative_path = artifact_id
                yield verified
        except AuditArchiveSourceError:
            raise
        except AuditPathPolicyError as exc:
            raise AuditArchiveSourceError(
                "AUDIT_ARCHIVE_SOURCE_NOT_ALLOWED"
            ) from exc

    @contextmanager
    def resolve_request(self, *, request, tenant_id: str) -> Iterator[VerifiedFile]:
        artifact_id = getattr(request, "artifact_id", None)
        if artifact_id:
            with self.resolve_artifact(
                artifact_id=artifact_id,
                tenant_id=tenant_id,
            ) as verified:
                yield verified
            return

        root_id = getattr(request, "root_id", None)
        relative_path = getattr(request, "relative_path", None)
        if not root_id or not relative_path:
            raise AuditArchiveSourceError(
                "AUDIT_ARCHIVE_SOURCE_REFERENCE_REQUIRED"
            )
        try:
            with self._path_policy.open_verified_file(
                root_id=root_id,
                relative_path=relative_path,
            ) as verified:
                yield verified
        except AuditPathPolicyError as exc:
            raise AuditArchiveSourceError(
                "AUDIT_ARCHIVE_SOURCE_NOT_ALLOWED"
            ) from exc
