from conftest import headers
def test_owner_can_invite_and_guest_accepts(client):
    thread=client.post("/api/v2/threads",json={"title":"Sala"},headers=headers()).json()
    inv=client.post(f"/api/v2/threads/{thread['id']}/invitations",
      json={"email":"guest@example.com","role":"participant"},headers=headers())
    assert inv.status_code==200
    token=inv.json()["invitation_url"].rsplit("/",1)[-1]
    accepted=client.post("/api/v2/invitations/accept",json={"token":token},
      headers=headers(user="user-2",roles="member"))
    assert accepted.status_code==200
    again=client.post("/api/v2/invitations/accept",json={"token":token},
      headers=headers(user="user-2",roles="member"))
    assert again.status_code==409
def test_wrong_email_is_blocked(client):
    thread=client.post("/api/v2/threads",json={},headers=headers()).json()
    inv=client.post(f"/api/v2/threads/{thread['id']}/invitations",
      json={"email":"other@example.com"},headers=headers()).json()
    token=inv["invitation_url"].rsplit("/",1)[-1]
    r=client.post("/api/v2/invitations/accept",json={"token":token},
      headers=headers(user="user-2",roles="member"))
    assert r.status_code==403
