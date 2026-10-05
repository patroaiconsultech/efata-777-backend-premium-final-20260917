from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from orkio_v2.auth import Principal
from orkio_v2.config import Settings, get_settings
from orkio_v2.database import Base
from orkio_v2.models import (
    AuditEvent,
    KnowledgeDocument,
    KnowledgeStatus,
    KnowledgeStorageCleanup,
    Membership,
    Message,
    Tenant,
    User,
)
from orkio_v2.routes import _history
from orkio_v2.services.blob_storage import BlobStorageError, LocalBlobStorage
from orkio_v2.services.knowledge_policy import KnowledgePolicyError
from orkio_v2.services import knowledge_repository as repository
from orkio_v2.services.knowledge_repository import (
    create_uploaded_document,
    delete_document,
    get_managed_document,
    list_documents,
    list_versions,
    process_storage_cleanup_tasks,
    publish_document,
    revoke_document,
    supersede_document,
)
from orkio_v2.services.knowledge_retrieval import build_knowledge_context
from orkio_v2.services.team_runtime import team_history
from conftest import headers


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        session.add_all(
            [
                Tenant(id="tenant-a", name="Tenant A"),
                Tenant(id="tenant-b", name="Tenant B"),
                User(
                    id="admin-a",
                    external_subject="sub-admin-a",
                    email="admin-a@example.com",
                    display_name="Admin A",
                ),
                User(
                    id="user-a",
                    external_subject="sub-user-a",
                    email="user-a@example.com",
                    display_name="User A",
                ),
                User(
                    id="user-b",
                    external_subject="sub-user-b",
                    email="user-b@example.com",
                    display_name="User B",
                ),
                Membership(tenant_id="tenant-a", user_id="admin-a", role="admin"),
                Membership(tenant_id="tenant-a", user_id="user-a", role="member"),
                Membership(tenant_id="tenant-b", user_id="user-b", role="member"),
            ]
        )
        session.commit()
        yield session


def principal(
    user_id: str,
    tenant_id: str,
    *roles: str,
) -> Principal:
    return Principal(
        user_id=user_id,
        tenant_id=tenant_id,
        roles=tuple(roles or ("member",)),
        external_subject=f"sub-{user_id}",
        email=f"{user_id}@example.com",
    )


def settings(tmp_path: Path) -> Settings:
    return Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        PLATFORM_ARTIFACT_STORAGE_PATH=str(tmp_path),
        PLATFORM_KNOWLEDGE_PLANE_ENABLED=True,
    )


def create_doc(
    db,
    tmp_path: Path,
    *,
    actor: Principal,
    scope: str,
    text: str,
    title: str,
    agent_id: str | None = None,
    purposes: list[str] | None = None,
):
    return create_uploaded_document(
        db,
        principal=actor,
        scope=scope,
        title=title,
        filename=f"{title.lower().replace(' ', '-')}.txt",
        mime_type="text/plain",
        data=text.encode(),
        digest=None,
        classification="internal",
        allowed_purposes=purposes,
        agent_id=agent_id,
        expires_at=None,
        storage=LocalBlobStorage(tmp_path),
    )


def test_personal_is_active_and_cross_user_management_is_hidden(db, tmp_path):
    owner = principal("user-a", "tenant-a", "member")
    other = principal("user-b", "tenant-b", "member")
    row = create_doc(
        db,
        tmp_path,
        actor=owner,
        scope="PERSONAL",
        text="PERSONAL-A-ONLY",
        title="Personal A",
    )
    assert row.status == "ACTIVE"
    assert row.owner_user_id == "user-a"
    assert [item.id for item in list_documents(db, principal=owner, scope="PERSONAL")] == [
        row.id
    ]

    with pytest.raises(KnowledgePolicyError) as raised:
        delete_document(
            db,
            principal=other,
            document_id=row.id,
            storage=LocalBlobStorage(tmp_path),
        )
    assert raised.value.code == "KNOWLEDGE_NOT_FOUND"

    bundle = build_knowledge_context(
        db,
        settings=settings(tmp_path),
        tenant_id="tenant-b",
        user_id="user-b",
        purpose="chat",
        execution_id="exec-b",
        thread_id="thread-b",
        agent_id="orkio",
    )
    assert bundle is None


def test_institutional_publish_is_tenant_bound_and_usage_is_audited(db, tmp_path):
    admin = principal("admin-a", "tenant-a", "admin")
    row = create_doc(
        db,
        tmp_path,
        actor=admin,
        scope="INSTITUTIONAL",
        text="TENANT-A-INSTITUTIONAL-FACT",
        title="Institutional",
    )
    assert row.status == "DRAFT"

    active = publish_document(db, principal=admin, document_id=row.id)
    assert active.status == "ACTIVE"

    bundle = build_knowledge_context(
        db,
        settings=settings(tmp_path),
        tenant_id="tenant-a",
        user_id="user-a",
        purpose="chat",
        execution_id="exec-a",
        thread_id="thread-a",
        agent_id="orkio",
    )
    assert bundle is not None
    assert "TENANT-A-INSTITUTIONAL-FACT" in "\n".join(
        item["content"] for item in bundle.messages
    )

    assert build_knowledge_context(
        db,
        settings=settings(tmp_path),
        tenant_id="tenant-b",
        user_id="user-b",
        purpose="chat",
        execution_id="exec-b",
        thread_id="thread-b",
        agent_id="orkio",
    ) is None

    events = list(
        db.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "knowledge.used",
                AuditEvent.resource_id == row.id,
            )
        ).all()
    )
    assert events
    event = events[-1]
    assert event.metadata_json["execution_id"] == "exec-a"
    assert event.metadata_json["version"] == 1
    assert "content" not in event.metadata_json
    assert "prompt" not in event.metadata_json


def test_platform_requires_exact_platform_owner_and_is_global(db, tmp_path):
    mere_superadmin = principal("admin-a", "tenant-a", "superadmin", "admin")
    with pytest.raises(KnowledgePolicyError) as raised:
        create_doc(
            db,
            tmp_path,
            actor=mere_superadmin,
            scope="PLATFORM",
            text="GLOBAL-DIRECTIVE",
            title="Global",
        )
    assert raised.value.code == "KNOWLEDGE_PLATFORM_OWNER_REQUIRED"

    owner = principal("admin-a", "tenant-a", "admin", "platform_owner")
    draft = create_doc(
        db,
        tmp_path,
        actor=owner,
        scope="PLATFORM",
        text="GLOBAL-DIRECTIVE",
        title="Global",
    )
    assert draft.tenant_id is None
    publish_document(db, principal=owner, document_id=draft.id)

    bundle = build_knowledge_context(
        db,
        settings=settings(tmp_path),
        tenant_id="tenant-b",
        user_id="user-b",
        purpose="chat",
        execution_id="exec-global",
        thread_id="thread-b",
        agent_id="orkio",
    )
    assert bundle is not None
    assert "GLOBAL-DIRECTIVE" in "\n".join(item["content"] for item in bundle.messages)


def test_supersede_is_versioned_then_revoke_removes_context(db, tmp_path):
    admin = principal("admin-a", "tenant-a", "admin")
    old = create_doc(
        db,
        tmp_path,
        actor=admin,
        scope="INSTITUTIONAL",
        text="VERSION-ONE",
        title="Policy",
    )
    old = publish_document(db, principal=admin, document_id=old.id)

    new = supersede_document(
        db,
        principal=admin,
        document_id=old.id,
        title=None,
        filename="policy-v2.txt",
        mime_type="text/plain",
        data=b"VERSION-TWO",
        digest=None,
        classification=None,
        allowed_purposes=None,
        agent_id=None,
        expires_at=None,
        storage=LocalBlobStorage(tmp_path),
    )
    db.refresh(old)
    assert old.status == KnowledgeStatus.superseded.value
    assert new.status == KnowledgeStatus.active.value
    assert new.version == 2
    assert new.logical_document_id == old.logical_document_id
    assert new.supersedes_id == old.id

    bundle = build_knowledge_context(
        db,
        settings=settings(tmp_path),
        tenant_id="tenant-a",
        user_id="user-a",
        purpose="chat",
        execution_id="exec-v2",
        thread_id="thread-a",
        agent_id="orkio",
    )
    assert bundle is not None
    combined = "\n".join(item["content"] for item in bundle.messages)
    assert "VERSION-TWO" in combined
    assert "VERSION-ONE" not in combined

    revoked = revoke_document(db, principal=admin, document_id=new.id)
    assert revoked.status == KnowledgeStatus.revoked.value
    assert build_knowledge_context(
        db,
        settings=settings(tmp_path),
        tenant_id="tenant-a",
        user_id="user-a",
        purpose="chat",
        execution_id="exec-after-revoke",
        thread_id="thread-a",
        agent_id="orkio",
    ) is None



def test_expired_knowledge_is_excluded_and_supersede_inherits_expiry(db, tmp_path):
    admin = principal("admin-a", "tenant-a", "admin")
    row = create_doc(
        db,
        tmp_path,
        actor=admin,
        scope="INSTITUTIONAL",
        text="TIME-BOUND-POLICY",
        title="Timed",
    )
    row.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    db.commit()
    row = publish_document(db, principal=admin, document_id=row.id)

    replacement = supersede_document(
        db,
        principal=admin,
        document_id=row.id,
        title=None,
        filename="timed-v2.txt",
        mime_type="text/plain",
        data=b"TIME-BOUND-POLICY-V2",
        digest=None,
        classification=None,
        allowed_purposes=None,
        agent_id=None,
        expires_at=None,
        storage=LocalBlobStorage(tmp_path),
    )
    assert replacement.expires_at is not None
    inherited = replacement.expires_at
    if inherited.tzinfo is None:
        inherited = inherited.replace(tzinfo=timezone.utc)
    assert inherited > datetime.now(timezone.utc)

    replacement.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    assert build_knowledge_context(
        db,
        settings=settings(tmp_path),
        tenant_id="tenant-a",
        user_id="user-a",
        purpose="chat",
        execution_id="exec-expired",
        thread_id="thread-a",
        agent_id="orkio",
    ) is None

def test_precedence_platform_institutional_agent_personal(db, tmp_path):
    admin = principal("admin-a", "tenant-a", "admin")
    owner = principal("admin-a", "tenant-a", "admin", "platform_owner")
    user = principal("user-a", "tenant-a", "member")

    platform = create_doc(
        db, tmp_path, actor=owner, scope="PLATFORM", text="LAYER-PLATFORM", title="P"
    )
    publish_document(db, principal=owner, document_id=platform.id)
    institutional = create_doc(
        db,
        tmp_path,
        actor=admin,
        scope="INSTITUTIONAL",
        text="LAYER-INSTITUTIONAL",
        title="I",
    )
    publish_document(db, principal=admin, document_id=institutional.id)
    agent = create_doc(
        db,
        tmp_path,
        actor=admin,
        scope="INSTITUTIONAL",
        text="LAYER-AGENT",
        title="A",
        agent_id="orkio",
    )
    publish_document(db, principal=admin, document_id=agent.id)
    create_doc(
        db, tmp_path, actor=user, scope="PERSONAL", text="LAYER-PERSONAL", title="U"
    )

    bundle = build_knowledge_context(
        db,
        settings=settings(tmp_path),
        tenant_id="tenant-a",
        user_id="user-a",
        purpose="chat",
        execution_id="exec-order",
        thread_id="thread-a",
        agent_id="orkio",
    )
    assert bundle is not None
    joined = "\n".join(message["content"] for message in bundle.messages)
    assert joined.index("LAYER-PLATFORM") < joined.index("LAYER-INSTITUTIONAL")
    assert joined.index("LAYER-INSTITUTIONAL") < joined.index("LAYER-AGENT")
    assert joined.index("LAYER-AGENT") < joined.index("LAYER-PERSONAL")
    by_layer = {
        next(
            name
            for name in ("PATROAI_PLATFORM", "INSTITUTIONAL", "AGENT_SCOPED", "PERSONAL")
            if f"GOVERNED KNOWLEDGE LAYER — {name}" in message["content"]
        ): message
        for message in bundle.messages
    }
    assert by_layer["PATROAI_PLATFORM"]["role"] == "system"
    for layer in ("INSTITUTIONAL", "AGENT_SCOPED", "PERSONAL"):
        assert by_layer[layer]["role"] == "user"
        assert "UNTRUSTED_KNOWLEDGE_CONTENT" in by_layer[layer]["content"]


def test_chat_and_team_history_share_governed_retrieval(db, tmp_path):
    admin = principal("admin-a", "tenant-a", "admin")
    row = create_doc(
        db,
        tmp_path,
        actor=admin,
        scope="INSTITUTIONAL",
        text="SHARED-KNOWLEDGE-CONTEXT",
        title="Shared",
    )
    publish_document(db, principal=admin, document_id=row.id)
    db.add(
        Message(
            tenant_id="tenant-a",
            thread_id="thread-shared",
            author_type="user",
            author_id="user-a",
            content="Use a base autorizada.",
        )
    )
    db.commit()
    cfg = settings(tmp_path)

    chat = _history(
        db,
        "thread-shared",
        "tenant-a",
        cfg,
        user_id="user-a",
        execution_id="exec-chat",
        agent_id="orkio",
        purpose="chat",
    )
    team = team_history(
        db,
        thread_id="thread-shared",
        tenant_id="tenant-a",
        settings=cfg,
        user_id="user-a",
        execution_id="exec-team",
        agent_id="orkio",
        purpose="team",
    )
    assert "SHARED-KNOWLEDGE-CONTEXT" in "\n".join(
        str(item.get("content", "")) for item in chat
    )
    assert "SHARED-KNOWLEDGE-CONTEXT" in "\n".join(
        str(item.get("content", "")) for item in team
    )


def test_purpose_filter_is_fail_closed(db, tmp_path):
    user = principal("user-a", "tenant-a", "member")
    create_doc(
        db,
        tmp_path,
        actor=user,
        scope="PERSONAL",
        text="CHAT-ONLY",
        title="Chat",
        purposes=["chat"],
    )
    assert build_knowledge_context(
        db,
        settings=settings(tmp_path),
        tenant_id="tenant-a",
        user_id="user-a",
        purpose="realtime",
        execution_id="exec-rt",
        thread_id="thread",
        agent_id="orkio",
    ) is None
    assert build_knowledge_context(
        db,
        settings=settings(tmp_path),
        tenant_id="tenant-a",
        user_id="user-a",
        purpose="chat",
        execution_id="exec-chat",
        thread_id="thread",
        agent_id="orkio",
    ) is not None


def test_alembic_has_one_effective_head_and_legacy_claim_is_not_in_graph():
    root = Path(__file__).resolve().parents[1]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    script = ScriptDirectory.from_config(cfg)
    assert script.get_heads() == ["013_agent_studio_control_plane"]
    revisions = {revision.revision for revision in script.walk_revisions()}
    assert "005_legacy_claim_on_demand" not in revisions
    assert not (root / "005_legacy_claim_on_demand.py").exists()


def test_http_routes_materialize_personal_and_institutional_destinations(
    client, tmp_path, monkeypatch
):
    cfg = get_settings()
    monkeypatch.setattr(cfg, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(cfg, "knowledge_plane_enabled", True, raising=False)

    personal = client.post(
        "/api/v2/knowledge",
        headers=headers(),
        data={"scope": "PERSONAL", "title": "Minha base"},
        files={"file": ("mine.txt", b"HTTP-PERSONAL", "text/plain")},
    )
    assert personal.status_code == 200, personal.text
    assert personal.json()["status"] == "ACTIVE"

    institutional = client.post(
        "/api/v2/knowledge",
        headers=headers(),
        data={"scope": "INSTITUTIONAL", "title": "Institucional"},
        files={"file": ("institutional.txt", b"HTTP-INSTITUTIONAL", "text/plain")},
    )
    assert institutional.status_code == 200, institutional.text
    assert institutional.json()["status"] == "DRAFT"

    published = client.post(
        f"/api/v2/knowledge/{institutional.json()['id']}/publish",
        headers=headers(),
    )
    assert published.status_code == 200, published.text
    assert published.json()["status"] == "ACTIVE"

    listing = client.get(
        "/api/v2/knowledge?scope=INSTITUTIONAL",
        headers=headers(),
    )
    assert listing.status_code == 200
    assert institutional.json()["id"] in {item["id"] for item in listing.json()["items"]}


def test_http_platform_destination_requires_canonical_platform_owner(
    client, tmp_path, monkeypatch
):
    cfg = get_settings()
    monkeypatch.setattr(cfg, "artifact_storage_path", str(tmp_path), raising=False)
    monkeypatch.setattr(cfg, "knowledge_plane_enabled", True, raising=False)
    monkeypatch.setattr(cfg, "platform_owner_subject", "", raising=False)

    denied = client.post(
        "/api/v2/knowledge",
        headers=headers(),
        data={"scope": "PLATFORM", "title": "Diretriz"},
        files={"file": ("directive.txt", b"GLOBAL", "text/plain")},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "KNOWLEDGE_PLATFORM_OWNER_REQUIRED"

    monkeypatch.setattr(cfg, "platform_owner_subject", "sub-1", raising=False)
    allowed = client.post(
        "/api/v2/knowledge",
        headers=headers(),
        data={"scope": "PLATFORM", "title": "Diretriz"},
        files={"file": ("directive.txt", b"GLOBAL", "text/plain")},
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["status"] == "DRAFT"


class _DeleteFailStorage:
    def __init__(self, delegate):
        self.delegate = delegate

    def put_if_absent(self, key, data, *, content_type):
        return self.delegate.put_if_absent(key, data, content_type=content_type)

    def get(self, key):
        return self.delegate.get(key)

    def delete(self, key):
        raise BlobStorageError("BLOB_DELETE_FAILED")


def test_create_has_no_post_commit_refresh_compensation_window(db, tmp_path, monkeypatch):
    actor = principal("user-a", "tenant-a", "member")

    def forbidden_refresh(*_args, **_kwargs):
        raise AssertionError("create_uploaded_document must not refresh after commit")

    monkeypatch.setattr(db, "refresh", forbidden_refresh)
    row = create_doc(
        db,
        tmp_path,
        actor=actor,
        scope="PERSONAL",
        text="POST-COMMIT-SAFE",
        title="Post Commit Safe",
    )
    assert db.get(KnowledgeDocument, row.id) is not None
    assert LocalBlobStorage(tmp_path).get(row.storage_key) == b"POST-COMMIT-SAFE"


def test_supersede_has_no_post_commit_refresh_compensation_window(db, tmp_path, monkeypatch):
    admin = principal("admin-a", "tenant-a", "admin")
    old = create_doc(
        db,
        tmp_path,
        actor=admin,
        scope="INSTITUTIONAL",
        text="OLD",
        title="Old",
    )
    old = publish_document(db, principal=admin, document_id=old.id)

    def forbidden_refresh(*_args, **_kwargs):
        raise AssertionError("supersede_document must not refresh after commit")

    monkeypatch.setattr(db, "refresh", forbidden_refresh)
    new = supersede_document(
        db,
        principal=admin,
        document_id=old.id,
        title="New",
        filename="new.txt",
        mime_type="text/plain",
        data=b"NEW",
        digest=None,
        classification=None,
        allowed_purposes=None,
        agent_id=None,
        expires_at=None,
        storage=LocalBlobStorage(tmp_path),
    )
    assert db.get(KnowledgeDocument, new.id) is not None
    assert LocalBlobStorage(tmp_path).get(new.storage_key) == b"NEW"


def test_create_ambiguous_commit_that_persisted_keeps_blob_and_returns_row(
    db, tmp_path, monkeypatch
):
    actor = principal("user-a", "tenant-a", "member")
    original_commit = db.commit
    injected = {"done": False}

    def commit_then_raise():
        original_commit()
        if not injected["done"]:
            injected["done"] = True
            raise RuntimeError("synthetic transport failure after durable commit")

    monkeypatch.setattr(db, "commit", commit_then_raise)
    row = create_doc(
        db,
        tmp_path,
        actor=actor,
        scope="PERSONAL",
        text="AMBIGUOUS-COMMIT",
        title="Ambiguous",
    )
    assert db.get(KnowledgeDocument, row.id) is not None
    assert LocalBlobStorage(tmp_path).get(row.storage_key) == b"AMBIGUOUS-COMMIT"


def test_supersede_ambiguous_commit_keeps_new_blob_and_atomic_version_state(
    db, tmp_path, monkeypatch
):
    admin = principal("admin-a", "tenant-a", "admin")
    old = create_doc(
        db,
        tmp_path,
        actor=admin,
        scope="INSTITUTIONAL",
        text="V1",
        title="Policy",
    )
    old = publish_document(db, principal=admin, document_id=old.id)
    original_commit = db.commit
    injected = {"done": False}

    def commit_then_raise():
        original_commit()
        if not injected["done"]:
            injected["done"] = True
            raise RuntimeError("synthetic transport failure after durable commit")

    monkeypatch.setattr(db, "commit", commit_then_raise)
    new = supersede_document(
        db,
        principal=admin,
        document_id=old.id,
        title=None,
        filename="policy-v2.txt",
        mime_type="text/plain",
        data=b"V2",
        digest=None,
        classification=None,
        allowed_purposes=None,
        agent_id=None,
        expires_at=None,
        storage=LocalBlobStorage(tmp_path),
    )
    persisted_old = db.get(KnowledgeDocument, old.id)
    persisted_new = db.get(KnowledgeDocument, new.id)
    assert persisted_old is not None and persisted_old.status == "SUPERSEDED"
    assert persisted_new is not None and persisted_new.status == "ACTIVE"
    assert LocalBlobStorage(tmp_path).get(new.storage_key) == b"V2"


def test_management_queries_are_sql_scoped_even_if_post_fetch_policy_is_bypassed(
    db, tmp_path, monkeypatch
):
    owner = principal("user-a", "tenant-a", "member")
    other = principal("user-b", "tenant-b", "member")
    row = create_doc(
        db,
        tmp_path,
        actor=owner,
        scope="PERSONAL",
        text="TENANT-A",
        title="Tenant A",
    )
    monkeypatch.setattr(
        repository,
        "assert_document_visible_for_management",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(KnowledgePolicyError) as direct:
        get_managed_document(db, document_id=row.id, principal=other)
    assert direct.value.code == "KNOWLEDGE_NOT_FOUND"

    with pytest.raises(KnowledgePolicyError) as versions:
        list_versions(
            db,
            principal=other,
            logical_document_id=row.logical_document_id,
        )
    assert versions.value.code == "KNOWLEDGE_NOT_FOUND"


def test_model_constraints_reject_impossible_scope_tenant_owner_state(db):
    current = datetime.now(timezone.utc)
    row = KnowledgeDocument(
        id="invalid-platform-tenant",
        tenant_id="tenant-a",
        owner_user_id=None,
        scope="PLATFORM",
        agent_id=None,
        title="Invalid",
        source_filename="invalid.txt",
        mime_type="text/plain",
        size_bytes=1,
        sha256="a" * 64,
        storage_key="invalid/key",
        classification="internal",
        allowed_purposes=["chat"],
        logical_document_id="invalid-logical",
        version=1,
        status="DRAFT",
        effective_from=None,
        expires_at=None,
        created_by="user-a",
        approved_by=None,
        supersedes_id=None,
        created_at=current,
        updated_at=current,
    )
    db.add(row)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_delete_failure_is_queued_and_cleanup_is_processable(db, tmp_path):
    actor = principal("user-a", "tenant-a", "member")
    base_storage = LocalBlobStorage(tmp_path)
    row = create_doc(
        db,
        tmp_path,
        actor=actor,
        scope="PERSONAL",
        text="DELETE-ME",
        title="Delete Me",
    )

    delete_document(
        db,
        principal=actor,
        document_id=row.id,
        storage=_DeleteFailStorage(base_storage),
    )
    assert db.get(KnowledgeDocument, row.id) is None
    task = db.scalar(
        select(KnowledgeStorageCleanup).where(
            KnowledgeStorageCleanup.storage_key == row.storage_key
        )
    )
    assert task is not None
    assert task.status == "PENDING"
    assert base_storage.get(row.storage_key) == b"DELETE-ME"

    result = process_storage_cleanup_tasks(db, storage=base_storage)
    assert result == {"processed": 1, "failed": 0, "selected": 1}
    db.refresh(task)
    assert task.status == "DONE"
    with pytest.raises(BlobStorageError):
        base_storage.get(row.storage_key)


def test_missing_blob_emits_stable_observability_signal(db, tmp_path, caplog):
    admin = principal("admin-a", "tenant-a", "admin")
    row = create_doc(
        db,
        tmp_path,
        actor=admin,
        scope="INSTITUTIONAL",
        text="WILL-DISAPPEAR",
        title="Missing",
    )
    row = publish_document(db, principal=admin, document_id=row.id)
    LocalBlobStorage(tmp_path).delete(row.storage_key)

    with caplog.at_level("ERROR", logger="patroai.knowledge"):
        bundle = build_knowledge_context(
            db,
            settings=settings(tmp_path),
            tenant_id="tenant-a",
            user_id="user-a",
            purpose="chat",
            execution_id="exec-missing",
            thread_id="thread-missing",
            agent_id="orkio",
        )
    assert bundle is None
    assert "KNOWLEDGE_BLOB_MISSING" in caplog.text
    assert "metric=knowledge_blob_missing" in caplog.text


def test_chat_history_separates_immutable_system_guard_from_governed_platform(
    db, tmp_path
):
    owner = principal("admin-a", "tenant-a", "admin", "platform_owner")
    platform = create_doc(
        db,
        tmp_path,
        actor=owner,
        scope="PLATFORM",
        text="MUTABLE-GOVERNED-PLATFORM-DIRECTIVE",
        title="Governed Platform",
    )
    publish_document(db, principal=owner, document_id=platform.id)
    db.add(
        Message(
            tenant_id="tenant-a",
            thread_id="thread-platform-governance",
            author_type="user",
            author_id="user-a",
            content="A plataforma tem voz e realtime prontos?",
        )
    )
    db.commit()

    history = _history(
        db,
        "thread-platform-governance",
        "tenant-a",
        settings(tmp_path),
        user_id="user-a",
        execution_id="exec-platform-governance",
        agent_id="orkio",
        purpose="chat",
    )
    content = "\n".join(str(item.get("content", "")) for item in history)
    assert "SYSTEM_CAPABILITY_INTEGRITY" in content
    assert "MUTABLE-GOVERNED-PLATFORM-DIRECTIVE" in content
    assert "FOUNDER_SUPPLIED_INSTITUTIONAL_CONTEXT" not in content
    assert "CANONICAL_PLATFORM_CONTEXT" not in content
    assert content.index("SYSTEM_CAPABILITY_INTEGRITY") < content.index(
        "MUTABLE-GOVERNED-PLATFORM-DIRECTIVE"
    )
