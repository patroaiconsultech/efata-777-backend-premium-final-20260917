import asyncio
import json

import pytest

from orkio_v2.services import github_agent_tools as tool
from orkio_v2.services.github_integration import GitHubIntegrationError, RepositoryHead
from test_gate_e1_r1_github_agent_tools import settings


@pytest.mark.asyncio
async def test_round_budget_fails_closed_without_executing_last_tool(monkeypatch):
    async def head(s, repo):
        return RepositoryHead(repo, "main", "a" * 40, None)

    executed = []
    async def fake_execute(self, call):
        executed.append(call.call_id)
        return tool.ToolResult(call.call_id, '{"ok":true}', True)

    def response(call_id):
        return {"choices": [{"message": {"content": None, "tool_calls": [{
            "id": call_id, "type": "function",
            "function": {"name": "github_read", "arguments": json.dumps({
                "repository": "org/allowed", "commit_sha": "a" * 40,
                "operation": "tree"})}
        }]}}]}

    replies = iter([response("one"), response("two")])
    class FakeResponse:
        def raise_for_status(self): pass
        def json(self): return next(replies)
    class FakeClient:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def post(self, *args, **kw): return FakeResponse()

    monkeypatch.setattr(tool, "repository_head", head)
    monkeypatch.setattr(tool.ReadContext, "execute", fake_execute)
    monkeypatch.setattr(tool.httpx, "AsyncClient", FakeClient)
    with pytest.raises(GitHubIntegrationError, match="GITHUB_TOOL_ROUND_LIMIT"):
        await tool.prepare_github_tool_history(
            settings(), "orkio", [{"role": "user", "content": "read"}],
            tenant_id="tenant", user_id="user", execution_id="execution", is_admin=True)
    assert executed == ["one"]


def test_json_and_sse_both_handle_tool_errors():
    from pathlib import Path
    import inspect
    from orkio_v2 import routes
    source = inspect.getsource(routes)
    start = source.index("history = await prepare_github_tool_history(")
    end = source.index("answer=await llm.generate", start)
    catch = source.index("except (GitHubIntegrationError, asyncio.TimeoutError):", end)
    assert catch < source.index("except llm.LLMNotConfigured:", end)
    assert 'raise HTTPException(502, "GITHUB_TOOL_FAILED")' in source[catch:catch+200]
    assert source.count("except (GitHubIntegrationError, asyncio.TimeoutError):") >= 2
