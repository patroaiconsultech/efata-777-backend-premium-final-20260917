from conftest import Testing, headers
from sqlalchemy import select

from orkio_v2.models import Message, ThreadParticipant, ThreadRole


def test_me_exposes_authenticated_users_display_name(client):
    response = client.get("/api/v2/me", headers=headers())
    assert response.status_code == 200, response.text
    assert response.json()["display_name"] == "Owner"


def test_thread_history_exposes_human_display_names_scoped_to_participants(client):
    thread = client.post(
        "/api/v2/threads",
        json={"title": "Sala de nomes"},
        headers=headers(),
    )
    assert thread.status_code == 200, thread.text
    thread_id = thread.json()["id"]

    with Testing() as db:
        guest_participant = db.scalar(
            select(ThreadParticipant).where(
                ThreadParticipant.thread_id == thread_id,
                ThreadParticipant.user_id == "user-2",
            )
        )
        if guest_participant is None:
            db.add(
                ThreadParticipant(
                    tenant_id="tenant-1",
                    thread_id=thread_id,
                    user_id="user-2",
                    thread_role=ThreadRole.participant.value,
                    membership_type="external_guest",
                    history_access="from_join",
                    active=True,
                )
            )
        db.add_all(
            [
                Message(
                    tenant_id="tenant-1",
                    thread_id=thread_id,
                    author_type="user",
                    author_id="user-1",
                    content="owner-author-marker",
                ),
                Message(
                    tenant_id="tenant-1",
                    thread_id=thread_id,
                    author_type="user",
                    author_id="user-2",
                    content="guest-author-marker",
                ),
            ]
        )
        db.commit()

    response = client.get(
        f"/api/v2/threads/{thread_id}/messages",
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    by_content = {item["content"]: item for item in response.json()}

    owner = by_content["owner-author-marker"]
    assert owner["author_id"] == "user-1"
    assert owner["user_id"] == "user-1"
    assert owner["author_display_name"] == "Owner"

    guest = by_content["guest-author-marker"]
    assert guest["author_id"] == "user-2"
    assert guest["user_id"] == "user-2"
    assert guest["author_display_name"] == "Guest"


def test_history_does_not_disclose_unscoped_user_name_or_id(client):
    thread = client.post(
        "/api/v2/threads",
        json={"title": "Histórico com identidade não vinculada"},
        headers=headers(),
    )
    assert thread.status_code == 200, thread.text
    thread_id = thread.json()["id"]

    from orkio_v2.models import User

    with Testing() as db:
        if db.get(User, "user-unscoped") is None:
            db.add(
                User(
                    id="user-unscoped",
                    external_subject="sub-unscoped",
                    email="unscoped@example.com",
                    display_name="Private Outside User",
                )
            )
        db.add(
            Message(
                tenant_id="tenant-1",
                thread_id=thread_id,
                author_type="user",
                author_id="user-unscoped",
                content="unscoped-author-marker",
            )
        )
        db.commit()

    response = client.get(
        f"/api/v2/threads/{thread_id}/messages", headers=headers()
    )
    assert response.status_code == 200, response.text
    item = next(
        row for row in response.json()
        if row["content"] == "unscoped-author-marker"
    )
    assert item["author_display_name"] is None
    assert item["author_id"] is None
    assert item["user_id"] is None
