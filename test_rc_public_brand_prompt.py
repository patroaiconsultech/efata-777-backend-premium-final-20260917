from orkio_v2.services.llm_contracts import agent_system_prompt


def test_public_agent_prompts_do_not_emit_legacy_orkio_brand():
    for agent_id in ("orkio", "orion", "archangel_michael", "archangel_gabriel", "archangel_jophiel"):
        prompt = agent_system_prompt(agent_id)
        assert "ORKIO" not in prompt
        assert "PatroAI" in prompt
        assert "Plataforma Efatá 777" in prompt
