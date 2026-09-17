from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Artifact


def artifact_context_message(
    db: Session,
    *,
    tenant_id: str,
    thread_id: str,
    limit: int = 8,
) -> dict[str, str] | None:
    """Trusted runtime context for artifacts already committed to persistence.

    This is intentionally DB-derived. The LLM may confirm only the artifacts
    listed here and must not invent generation/download state.
    """
    rows = db.scalars(
        select(Artifact)
        .where(
            Artifact.tenant_id == tenant_id,
            Artifact.thread_id == thread_id,
        )
        .order_by(Artifact.created_at.desc(), Artifact.id.desc())
        .limit(limit)
    ).all()
    if not rows:
        return None

    lines = [
        "TRUSTED PERSISTED ARTIFACTS — server-confirmed runtime state.",
        "You MAY state that an artifact listed below was generated/persisted and is available via its exact download_path.",
        "Never claim an unlisted artifact exists. Never invent a URL.",
    ]
    for row in rows:
        lines.append(
            "artifact_id={id} filename={filename} mime_type={mime} sha256={sha} "
            "download_path=/api/v2/artifacts/{id}/download".format(
                id=row.id,
                filename=row.filename,
                mime=row.mime_type,
                sha=row.sha256,
            )
        )
    return {"role": "system", "content": "\n".join(lines)}
