from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from orkio_v2.config import Settings
from orkio_v2.database import Base
from orkio_v2.models import Tenant, User
from orkio_v2.services.builtin_agent_knowledge import (
    builtin_founder_knowledge_message,
)
from orkio_v2.services.knowledge_retrieval import knowledge_context_messages


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
                User(
                    id="founder-user",
                    external_subject="founder-subject",
                    email="founder@example.com",
                    display_name="Founder",
                ),
                User(
                    id="other-user",
                    external_subject="other-subject",
                    email="other@example.com",
                    display_name="Other",
                ),
            ]
        )
        session.commit()
        yield session


def settings(tmp_path: Path) -> Settings:
    return Settings(
        PLATFORM_ENVIRONMENT="test",
        PLATFORM_AUTH_MODE="test",
        PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
        PLATFORM_ARTIFACT_STORAGE_PATH=str(tmp_path),
        PLATFORM_KNOWLEDGE_PLANE_ENABLED=True,
        PLATFORM_OWNER_SUBJECT="founder-subject",
    )


def test_founder_query_gets_source_controlled_profile_as_data(db, tmp_path):
    message = builtin_founder_knowledge_message(
        db,
        settings=settings(tmp_path),
        user_id="other-user",
        agent_id="orkio",
        query_text="Quem é o Founder da PatroAI e da EFATÀ 777?",
    )
    assert message is not None
    assert message["role"] == "user"
    assert "Daniel Graebin" in message["content"]
    assert "EFATÀ 777" in message["content"]
    assert "DATA ONLY" in message["content"]
    assert "sha256=" in message["content"]


def test_unrelated_query_for_other_user_does_not_receive_founder_profile(db, tmp_path):
    message = builtin_founder_knowledge_message(
        db,
        settings=settings(tmp_path),
        user_id="other-user",
        agent_id="orkio",
        query_text="Qual é a previsão para a reunião de amanhã?",
    )
    assert message is None


def test_platform_owner_self_profile_query_receives_founder_profile(db, tmp_path):
    message = builtin_founder_knowledge_message(
        db,
        settings=settings(tmp_path),
        user_id="founder-user",
        agent_id="orkio",
        query_text="O que tu sabes sobre mim?",
    )
    assert message is not None
    assert message["role"] == "user"
    assert "Daniel Graebin" in message["content"]


def test_platform_owner_unrelated_query_does_not_pay_profile_context_cost(db, tmp_path):
    message = builtin_founder_knowledge_message(
        db,
        settings=settings(tmp_path),
        user_id="founder-user",
        agent_id="orkio",
        query_text="Qual é a pauta da reunião de amanhã?",
    )
    assert message is None


def test_other_agent_never_receives_founder_profile(db, tmp_path):
    message = builtin_founder_knowledge_message(
        db,
        settings=settings(tmp_path),
        user_id="founder-user",
        agent_id="orion",
        query_text="Quem é Daniel Graebin?",
    )
    assert message is None


def test_retrieval_includes_builtin_profile_even_without_db_knowledge(db, tmp_path):
    messages = knowledge_context_messages(
        db,
        settings=settings(tmp_path),
        tenant_id="tenant-a",
        user_id="other-user",
        purpose="realtime",
        execution_id="exec-1",
        thread_id="thread-1",
        agent_id="orkio",
        query_text="me fale sobre Daniel Graebin, founder da PatroAI",
    )
    assert len(messages) == 1
    assert messages[0]["role"] == "user"
    assert "Daniel Graebin" in messages[0]["content"]
    assert "Founder & CEO da PatroAI Consultech" in messages[0]["content"]
