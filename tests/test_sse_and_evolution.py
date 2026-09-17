from conftest import headers
def test_sse_has_terminal_done(client):
    thread=client.post("/api/v2/threads",json={},headers=headers()).json()
    response=client.post(f"/api/v2/threads/{thread['id']}/stream",json={"content":"oi"},headers=headers())
    assert "event: done" in response.text
def test_evolution_is_proposal_only(client):
    payload={"title":"Fix","issue_map":{"x":1},"patch_plan":{"files":[]},
    "risk_assessment":{"level":"low"},"rollback_plan":{"steps":[]},"smoke_plan":{"tests":[]}}
    r=client.post("/api/v2/evolution/proposals",json=payload,headers=headers())
    assert r.status_code==200
    body=r.json()
    assert body["proposal_only"] is True
    assert body["write_executed"] is False
