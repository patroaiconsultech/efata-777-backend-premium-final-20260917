from __future__ import annotations

import pytest
from conftest import headers
from orkio_v2.config import get_settings
from orkio_v2.services.team_runtime import (
    MAX_TEAM_CONTRIBUTORS,
    TeamContractError,
    build_team_plan,
    team_definition_payload,
)


@pytest.fixture()
def configured(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "openai_api_key", "contract-test-not-real", raising=False)
    monkeypatch.setattr(settings, "llm_primary_provider", "openai", raising=False)
    return settings


def test_catalog_policy_excludes_chair_and_publishes_backend_limits(client, configured):
    response = client.get("/api/v2/teams", headers=headers())
    assert response.status_code == 200
    general = next(item for item in response.json() if item["team_id"] == "general_team")
    assert general["orchestrator_agent_id"] == "orkio"
    assert "orkio" not in general["candidate_contributor_agent_ids"]
    policy = general["participant_policy"]
    assert policy["max_contributors"] == MAX_TEAM_CONTRIBUTORS == 8
    assert policy["min_contributors"] >= 1
    assert policy["eligible_count"] == len(general["candidate_contributor_agent_ids"])
    assert policy["select_all_supported"] is False


def test_server_resolves_chair_and_plan_contains_contributors_only(configured):
    plan = build_team_plan(
        team_id="general_team",
        selection_mode="explicit",
        contributor_agent_ids=["chris", "orion"],
        settings=configured,
    )
    assert plan.orchestrator_agent_id == "orkio"
    assert plan.contributor_agent_ids == ("chris", "orion")
    assert plan.orchestrator_agent_id not in plan.contributor_agent_ids


def test_chair_cannot_be_submitted_as_specialist_contributor(configured):
    with pytest.raises(TeamContractError, match="TEAM_CHAIR_AS_CONTRIBUTOR_FORBIDDEN") as exc:
        build_team_plan(
            team_id="general_team",
            selection_mode="explicit",
            contributor_agent_ids=["orkio", "orion"],
            settings=configured,
        )
    assert exc.value.code == "TEAM_CHAIR_AS_CONTRIBUTOR_FORBIDDEN"


def test_max_eight_and_all_eligible_fail_closed(configured):
    payload = team_definition_payload("general_team", configured)
    candidates = payload["candidate_contributor_agent_ids"]
    assert len(candidates) > 8

    with pytest.raises(TeamContractError, match="TEAM_MAX_CONTRIBUTORS_EXCEEDED"):
        build_team_plan(
            team_id="general_team",
            selection_mode="explicit",
            contributor_agent_ids=candidates[:9],
            settings=configured,
        )

    with pytest.raises(TeamContractError, match="TEAM_SELECT_ALL_NOT_SUPPORTED"):
        build_team_plan(
            team_id="general_team",
            selection_mode="all_eligible",
            contributor_agent_ids=[],
            settings=configured,
        )

def test_legacy_payload_cannot_weaken_minimum_real_contributors(configured):
    with pytest.raises(TeamContractError, match="TEAM_MIN_PARTICIPANTS_REQUIRED") as exc:
        build_team_plan(
            team_id="general_team",
            selection_mode="explicit",
            contributor_agent_ids=[],
            participant_agent_ids=["orkio", "orion"],
            settings=configured,
        )
    assert exc.value.code == "TEAM_MIN_PARTICIPANTS_REQUIRED"

    accepted = build_team_plan(
        team_id="general_team",
        selection_mode="explicit",
        contributor_agent_ids=[],
        participant_agent_ids=["orkio", "orion", "chris"],
        settings=configured,
    )
    assert accepted.orchestrator_agent_id == "orkio"
    assert accepted.contributor_agent_ids == ("orion", "chris")

