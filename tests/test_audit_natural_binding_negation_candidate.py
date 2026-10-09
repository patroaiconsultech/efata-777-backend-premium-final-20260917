from orkio_v2.services.audit_natural_binding import resolve_natural_audit_binding


def test_documental_explicitly_denies_runtime_trace_without_hijack():
    message = (
        "Auditor, revise apenas as contribuicoes anteriores. "
        "Nao solicito consulta a traces de runtime, logs, infraestrutura, "
        "execucao de ferramentas administrativas ou aprovacao de producao. "
        "Verifique seguranca e rastreabilidade documental."
    )
    assert resolve_natural_audit_binding(message, resolved_agent_id="auditor") is None


def test_affirmative_trace_intent_preserved():
    binding = resolve_natural_audit_binding(
        "Audite a ultima execucao e consulte os logs de runtime.",
        resolved_agent_id="auditor",
    )
    assert binding is not None
    assert binding.intent == "runtime.trace.get"
    assert binding.error_code == "CAPABILITY_UNAVAILABLE"


def test_negative_sentence_does_not_hide_separate_positive_trace_request():
    message = (
        "Nao solicito consulta a traces de runtime, logs. "
        "Mas audite a ultima execucao de runtime."
    )
    binding = resolve_natural_audit_binding(message, resolved_agent_id="auditor")
    assert binding is not None
    assert binding.intent == "runtime.trace.get"


def test_mixed_same_sentence_after_mas_preserves_positive_intent():
    message = "Nao solicito consulta a logs, mas audite a execucao de runtime."
    binding = resolve_natural_audit_binding(message, resolved_agent_id="auditor")
    assert binding is not None
    assert binding.intent == "runtime.trace.get"
    assert binding.error_code == "CAPABILITY_UNAVAILABLE"


def test_mixed_same_sentence_after_porem_preserves_positive_intent():
    message = "Nao quero acesso a traces, porem verifique os logs de runtime."
    binding = resolve_natural_audit_binding(message, resolved_agent_id="auditor")
    assert binding is not None
    assert binding.intent == "runtime.trace.get"
    assert binding.error_code == "CAPABILITY_UNAVAILABLE"


def test_documentary_negative_with_mas_non_runtime_stays_documentary():
    message = "Audite apenas o planejamento. Nao solicito consulta a logs, mas verifique a rastreabilidade documental."
    assert resolve_natural_audit_binding(message, resolved_agent_id="auditor") is None


def test_non_auditor_cannot_bind_natural_audit():
    message = "Audite a execucao de runtime."
    assert resolve_natural_audit_binding(message, resolved_agent_id="orion") is None


def test_mixed_same_sentence_after_e_audite_preserves_positive_intent():
    message = "Nao solicito consulta a logs e audite a execucao de runtime."
    binding = resolve_natural_audit_binding(message, resolved_agent_id="auditor")
    assert binding is not None
    assert binding.intent == "runtime.trace.get"
    assert binding.error_code == "CAPABILITY_UNAVAILABLE"


def test_denial_list_with_e_traces_stays_documental():
    message = "Audite o planejamento. Nao solicito consulta a logs e traces de runtime."
    assert resolve_natural_audit_binding(message, resolved_agent_id="auditor") is None


def test_mixed_same_sentence_after_e_verifique_preserves_positive_intent():
    message = "Nao solicito consulta a logs e verifique a execucao de runtime."
    binding = resolve_natural_audit_binding(message, resolved_agent_id="auditor")
    assert binding is not None
    assert binding.error_code == "CAPABILITY_UNAVAILABLE"


def test_r4_runtime_real_prompt_documental():
    message = (
        "AUDITOR — TESTE PRÁTICO R3-01. "
        "Faça uma auditoria exclusivamente documental do planejamento do Sistema de Gestão de Projetos. "
        "Verifique se recebeu contexto compartilhado e identifique riscos. "
        "Não estou solicitando consulta a logs, traces ou execução de operações de runtime. "
        "Apresente seu parecer documental normalmente."
    )
    assert resolve_natural_audit_binding(message, resolved_agent_id="auditor") is None


def test_r4_progressive_mixed_with_estou_solicitando():
    message = "Nao estou solicitando consulta a logs, mas audite a execucao de runtime."
    binding = resolve_natural_audit_binding(message, resolved_agent_id="auditor")
    assert binding is not None and binding.error_code == "CAPABILITY_UNAVAILABLE"


def test_r4_progressive_mixed_e_audite():
    message = "Nao estou solicitando consulta a logs e audite a execucao de runtime."
    binding = resolve_natural_audit_binding(message, resolved_agent_id="auditor")
    assert binding is not None and binding.error_code == "CAPABILITY_UNAVAILABLE"


def test_r4_progressive_denial_list_e_traces():
    message = "Verifique o planejamento. Nao estou solicitando consulta a logs e traces de runtime."
    assert resolve_natural_audit_binding(message, resolved_agent_id="auditor") is None
