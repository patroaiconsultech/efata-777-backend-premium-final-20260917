# EFATÀ 777 — DG-01 / AO-01 — ensaio P0 B2.1, SOMENTE STAGING

**Status:** PROPOSAL_ONLY · **Execução PostgreSQL real:** NÃO EXECUTADA · **Produção:** NO-GO  
**Backend-base:** `915bdc6186f36b759b21a6fe15ae6aa2bc6b330b`  
**Branch reservada:** `ensaio/p0-schema-colaboracao-20261017` (não contém este patch enquanto não houver commit autorizado).

## 1. Escopo da B2.1

Não altera `migrations/versions/014_thread_agent_grants.py`, `015_thread_collaboration_capabilities.py`, `016_thread_participant_access_expiry.py`. Script **CREATE** `scripts/p0_b2_alembic_capacity_preflight.py`; teste **CREATE** `tests/test_p0_b2_capacity_preflight.py`. Não executa Alembic, não cria schema 013 e não insere dados.

**Diferença B2 → B2.1:** `--apply` agora executa, sempre na mesma conexão SQLAlchemy:
1. Transação #1: `SET TRANSACTION READ ONLY`, `_inspect` (identidade cluster, banco, revisão 013/014, schema/colunas), ROLLBACK.
2. Transação #2: `SET LOCAL` timeouts → `_inspect` **ANTES DE LOCK EXCLUSIVO**, comparação com #1 → `LOCK TABLE public.alembic_version IN ACCESS EXCLUSIVE MODE NOWAIT` → `_inspect` **APÓS LOCK**, comparação com estado pré-lock → `ALTER TABLE ... VARCHAR(64)` se necessário → pós-check → COMMIT.
3. Qualquer erro antes do COMMIT => ROLLBACK e interrupção. Falha de permissão em `pg_control_system()` é condição **STOP**. Não conceder privilégio automaticamente.

A inspeção SQL pode obter locks **implícitos ACCESS SHARE**, normais de `SELECT`; a garantia é que **nenhum lock explícito ACCESS EXCLUSIVE** é solicitado antes de revalidar o destino na segunda transação. `NOWAIT` recusa lock incompatível; não elimina esperas em outras queries nem a duração de DDL.

## 2. Pré-gates obrigatórios, ainda pendentes

- AO-01 revisar B2.1, diff, 52 testes simulados e autorizar o **commit apenas na branch de ensaio**; operador também autorizar. Não houve commit.
- Confirmar que `backend-web01` continua sem deployment; referências de variáveis de staging são resolvidas só no runtime; não copiar produção.
- Registrar **fonte imutável** de schema físico 013 em PostgreSQL independente. O banco `postgres-web01` observado estava vazio. **Proibido** `alembic stamp 013` em banco vazio ou `create_all` com ORM moderno: isso mascara divergências.
- Criar/popular **somente** uma instância descartável de staging com schema 013 fiel, dois tenants e conversas/mensagens/convites sintéticos. Garantir testes de ACL negativos.
- Comprovar restaurabilidade de snapshot desse staging em **outro clone descartável**; comparar schema, contagens e dados sintéticos antes/depois.
- Verificar que não há migrations ou DDL automáticos no startup do backend de teste. Congelar writes durante S1–S3.
- Verificar que backend/runner de teste tem acesso apenas a banco de staging e variáveis próprias.
- Segurança: não compartilhar URL ou credenciais; nunca ampliar permissões da conta produtiva para satisfazer o script.

## 3. Identidades a verificar (observadas em capturas anteriores)

| Instância | `system_identifier` |
|---|---|
| `staging-web01 / postgres-web01` | `7696494375094112315` |
| `production / Postgres` | `7685726733043150913` |

O script B2.1 exige o staging e recusa explicitamente produção. A identidade do **processo executor** deve ser comprovada; conhecer um ID da interface não basta.

## 4. Consultas permitidas na fase S0 — SOMENTE LEITURA

Executar no **banco de staging** com a **mesma conta usada pelo futuro runner**; nenhuma variável secreta em capturas:

```sql
SELECT current_database(), current_schema(), pg_is_in_recovery();
SELECT system_identifier FROM pg_control_system();
SELECT has_function_privilege(current_user, 'pg_catalog.pg_control_system()', 'EXECUTE')
       AS can_read_cluster_identity;
SELECT version_num FROM public.alembic_version;
SELECT data_type, character_maximum_length, is_nullable
FROM information_schema.columns
WHERE table_schema='public' AND table_name='alembic_version' AND column_name='version_num';
```

**Observação:** essas consultas só fazem sentido depois da instalação de um schema 013 real. O identificador pode ser verificado antes, mas `alembic_version` não existe hoje no banco vazio. Se `pg_control_system()` for negado, registrar `PRIVILEGE_BLOCKED`, manter NO-GO e avaliar fonte de identidade segura com AO-01; **não remover a guarda do script para fazê-lo passar**.

## 5. S1 — inspect, SEM WRITE (só após S0)

Em runner provisionado no staging com branch/código auditados, PostgreSQL isolado e variáveis resolvidas:

```bash
python scripts/p0_b2_alembic_capacity_preflight.py --expected-database '<NOME_VALIDADO_DO_BANCO_STAGING>'
```

O comando padrão abre transação READ ONLY e reporta JSON sanitizado. Guardar `system_identifier`, `initial_revision`, `initial_version_length` e SHA do código. Revisão inicial permitida: `013_agent_studio_control_plane` ou `014_thread_agent_grants`; em 014 as duas colunas `allowed_agent_ids` devem existir.

## 6. S2 — ensaio de mudança de capacidade (exige NOVO gate)

**Não executar esta linha agora.** Após aprovação específica AO-01/operador para WRITE em staging e snapshot restaurado em clone:

```bash
python scripts/p0_b2_alembic_capacity_preflight.py \
  --apply \
  --expected-database '<NOME_VALIDADO_DO_BANCO_STAGING>' \
  --approval-id '<ID_REAL_DO_GATE>' \
  --acknowledge-staging-only 'B2-ONLY-STAGING-NO-PRODUCTION'
```

Conferir `version_num VARCHAR(64)` e revisão **inalterada**. O comando não roda migrations oficiais.

Testes negativos obrigatórios, num clone descartável:
- Alterar contexto de alvo entre inspeções (ou simulação instrumentada): **nenhum `LOCK TABLE` e nenhum DDL**.
- Modificar revisão 013/014 em transação concorrente antes do lock: recusa por estado divergente; se a mudança ocorrer depois da inspeção pré-lock, revalidação pós-lock falha.
- Sessão independente manter lock incompatível sobre `alembic_version`; `NOWAIT` deve falhar sem DDL.
- Induzir falha entre DDL e COMMIT; provar com SQL posterior que largura original foi restaurada pela transação.
- Usar conta sem permissão de `pg_control_system()` e confirmar recusa sem elevação de privilégio.
- Medir `lock_timeout`, duração da operação e ausência de efeito em outras tabelas.

Os testes unitários do pacote exercitam essas rotas **com mocks**. Ainda falta comprovação de concorrência em PostgreSQL verdadeiro.

## 7. S3 — migrations originais, gates independentes

Após S2 e nova autorização de migration em STAGING, executar **sequencialmente**, com leitura de metadados/ACL entre cada etapa:

```bash
alembic upgrade 014_thread_agent_grants
# checkpoint físico / semântica legacy de allowed_agent_ids

alembic upgrade 015_thread_collaboration_capabilities
# checkpoint de leitura/escrita, NULL e participantes antigos

alembic upgrade 016_thread_participant_access_expiry
# checkpoint de expiração, convites e constraint
```

**Se a revisão inicial já for 014:** não reexecutar 014. Se qualquer etapa falhar: STOP, registrar primeira divergência, **restaurar snapshot ensaiado**; não usar `alembic stamp` ou `alembic downgrade` como reparo.

## 8. S4 — provas de funcionalidade / fail-closed

Com backend de staging apontando somente para PostgreSQL/Redis de staging e autenticação de teste:
- GET conversas existentes sintéticas; POST nova conversa e participante; GET histórico.
- Verificar transação de POST falho (nenhuma thread residual).
- Testes cruzados tenant A/B, usuário convidado/não convidado, leitura/escrita, anexos, grants por agente, expiração e SSE.
- Mensagem Josué e handoff José: observar payload COMPLETO do modelo; não tornar `participant` opcional nem duplicar mensagem.
- Regressão CI e segurança permanecem gates próprios; cinco FAIL do Core CI e achados Bandit/segredos **não são considerados PASS**.

## 9. Rollback / recuperação

Script B2.1: erro antes do commit deve ser revertido pelo PostgreSQL; o teste local só simula. A coluna ampliada `VARCHAR(64)` pode permanecer se revisão ainda 013; **não encolher por tentativa**. Falha posterior de migration: restauração integral do clone/snapshot validado e testes de dados sintéticos e ACL; não usar downgrade destrutivo.

## 10. Handoff

Evidências exigidas para AO-01: source commit e hashes das 014–016, `system_identifier` da conexão efetiva, banco/schema, SQL metadata antes/depois, logs sem secrets, status/latência de 013→016, prova de concorrência real, ACL negativa e restauração. Sem isso: `POSTGRESQL_RUNTIME=NÃO_PROVADO`, `PRODUÇÃO=NO-GO`.
