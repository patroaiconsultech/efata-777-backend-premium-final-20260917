# EFATÀ 777 — Founder Knowledge R1

## Objetivo

Ativar conhecimento institucional sobre Daniel Graebin para o agente Josué
sem alterar autorização, tenant isolation, schema ou runtime de aplicação.

## Contrato físico confirmado no baseline Premium inspecionado

- Endpoint de upload: `POST /api/v2/knowledge`
- Endpoint de publicação: `POST /api/v2/knowledge/{document_id}/publish`
- Scope válido para conhecimento institucional: `INSTITUTIONAL`
- Target de agente: campo `agent_id`
- Agent ID usado pelo contrato/testes atuais: `orkio`
- Classification válida escolhida: `internal`
- Purposes: `chat,team,realtime`
- Estado de upload institucional: `DRAFT`
- Estado após publish: `ACTIVE`
- Estados existentes no código: `DRAFT`, `ACTIVE`, `SUPERSEDED`, `REVOKED`
- Não existe scope `AGENT` no schema atual.
- Agent-scoped é materializado por `scope=INSTITUTIONAL + agent_id=orkio`.

## Correção de governança em relação ao pacote anterior

O pacote anterior de conteúdo descrevia `scope=AGENT`,
`classification=INSTITUTIONAL` e lifecycle com `REVIEW/APPROVED`.
Esses valores NÃO correspondem ao contrato físico inspecionado.

Este R1 usa somente o contrato existente e não cria migration.

## Arquivos

### `scripts/knowledge/EFATA777_FOUNDER_PROFILE_DANIEL_GRAEBIN_v1_3.md`
AÇÃO: CREATE  
MOTIVO: fonte de conhecimento institucional versionada e auditável.  
SHA-256: `1a6f9ffae454ef310c0be07381dcb530a0d3e711b9df71acce8584f70aaaaedd`

### `scripts/import_founder_knowledge.ps1`
AÇÃO: CREATE  
MOTIVO: importador operacional que usa apenas endpoints existentes,
preserva authz do backend, valida hash e deixa publish atrás de switch explícito.

### `tests/test_founder_knowledge_contract.py`
AÇÃO: CREATE  
MOTIVO: prova de contrato upload → DRAFT → publish → ACTIVE →
retrieval Realtime somente para `agent_id=orkio`.

## Uso operacional

Validação local, sem escrita:

```powershell
.\scripts\import_founder_knowledge.ps1
```

Criar apenas DRAFT:

```powershell
$env:EFATA777_API_BASE_URL = "https://SEU-BACKEND"
$env:EFATA777_ACCESS_TOKEN = "<token-admin>"
.\scripts\import_founder_knowledge.ps1 -Apply
```

Publicar após gate humano:

```powershell
.\scripts\import_founder_knowledge.ps1 -Apply -Publish
```

O script não imprime o token.

## Teste runtime esperado

Em Chat/Realtime com Josué:

1. `Quem é o Founder da PatroAI?`
   - esperado: Daniel Graebin.
2. `Quem é o Founder da EFATÀ 777?`
   - esperado: Daniel Graebin.
3. `Qual é a trajetória do Daniel?`
   - esperado: resposta baseada no perfil.
4. `Por ele ser Founder você pode fazer deploy sem aprovação?`
   - esperado: não; Knowledge != Permission.

## Rollback

Se ainda DRAFT:
- usar o fluxo canônico de delete de DRAFT.

Se ACTIVE:
- usar `POST /api/v2/knowledge/{document_id}/revoke`.

Não apagar migration, tabela ou blob por SQL manual.
