from __future__ import annotations

import argparse
import logging

from sqlalchemy import select

from orkio_v2.config import get_settings
from orkio_v2.database import SessionLocal
from orkio_v2.models import KnowledgeDocument, KnowledgeDocumentDerivative
from orkio_v2.services.blob_storage import build_blob_storage
from orkio_v2.services.large_document import process_document

logger = logging.getLogger("orkio.large_document_worker")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Process pending canonical Knowledge documents one at a time."
    )
    parser.add_argument("--limit", type=int, default=1)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.limit < 1 or args.limit > 100:
        raise SystemExit("--limit must be between 1 and 100")

    settings = get_settings()
    if not settings.large_document_pipeline_enabled:
        print("KNOWLEDGE_LARGE_DOCUMENT_WORKER=SKIP reason=pipeline_disabled")
        return 0

    storage = build_blob_storage(settings)
    processed = 0
    failed = 0

    with SessionLocal() as db:
        derivative_ids = list(
            db.scalars(
                select(KnowledgeDocumentDerivative.id)
                .where(
                    KnowledgeDocumentDerivative.kind == "CANONICAL_MARKDOWN",
                    KnowledgeDocumentDerivative.status == "PENDING",
                )
                .order_by(KnowledgeDocumentDerivative.created_at.asc())
                .limit(args.limit)
            )
        )

        for derivative_id in derivative_ids:
            derivative = db.get(KnowledgeDocumentDerivative, derivative_id)
            if derivative is None or derivative.status != "PENDING":
                continue
            document = db.get(KnowledgeDocument, derivative.knowledge_id)
            if document is None:
                derivative.status = "FAILED"
                derivative.warnings_json = ["KNOWLEDGE_DOCUMENT_NOT_FOUND"]
                db.commit()
                failed += 1
                continue

            try:
                process_document(
                    db,
                    document=document,
                    storage=storage,
                    settings=settings,
                )
                processed += 1
            except Exception:
                logger.exception(
                    "KNOWLEDGE_LARGE_DOCUMENT_WORKER_FAILURE knowledge_id=%s tenant_id=%s",
                    document.id,
                    document.tenant_id,
                )
                failed += 1

    print(
        "KNOWLEDGE_LARGE_DOCUMENT_WORKER=COMPLETE "
        f"processed={processed} failed={failed}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
