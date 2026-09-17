from __future__ import annotations

from orkio_v2.models import Artifact
from orkio_v2.services.artifact_context import artifact_context_message
from orkio_v2.database import get_db


def test_persisted_artifact_context_is_db_derived_and_exact(client):
    dependency = client.app.dependency_overrides[get_db]
    gen = dependency()
    db = next(gen)
    try:
        row = Artifact(
            id="artifact-runtime-1",
            tenant_id="tenant-1",
            thread_id="thread-artifact",
            created_by="user-1",
            filename="resumo.docx",
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            sha256="a" * 64,
            storage_key="tenant-1/thread-artifact/generated/resumo.docx",
            version=1,
        )
        db.add(row)
        db.commit()

        msg = artifact_context_message(
            db,
            tenant_id="tenant-1",
            thread_id="thread-artifact",
        )
        assert msg is not None
        body = msg["content"]
        assert "TRUSTED PERSISTED ARTIFACTS" in body
        assert "artifact_id=artifact-runtime-1" in body
        assert "filename=resumo.docx" in body
        assert "/api/v2/artifacts/artifact-runtime-1/download" in body
        assert "a" * 64 in body

        assert artifact_context_message(
            db,
            tenant_id="tenant-2",
            thread_id="thread-artifact",
        ) is None
    finally:
        try:
            next(gen)
        except StopIteration:
            pass
