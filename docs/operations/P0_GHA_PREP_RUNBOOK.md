# EFATÀ 777 — Procedimento proposto: consolidar proveniência com GitHub Actions (SEM executar ainda)

**Gate atual AO-01:** GO para preparar artefatos; HOLD commit, push, alteração de variáveis do GitHub, `Run workflow`, execução do qualificador e Railway. Consultar `P0_GHA05_BOOTSTRAP_PUBLICACAO.md` antes de qualquer intenção de publicar.

## Arquivos/ações
- `CREATE .github/workflows/05-p0-provenance-prep.yml`: workflow isolado apenas manual.
- `CREATE scripts/p0_validate_wheelhouse.py`: compara SHA, versão, tags completas e completude 1:1 dos pacotes aplicáveis do lock (71 totais, 69 Linux CPython 3.12) com wheels do interpretador Linux/amd64 Python 3.12.
- `CREATE scripts/p0_verify_oci_manifest.py`: valida manifesto OCI e sua plataforma.
- `UNMODIFIED .github/workflows/03-postgres-integration.yml`: CI PG16 permanece byte a byte intacto.
- `UNMODIFIED requirements-test.lock.txt`: exige SHA-256 B39 fixo; falha se divergente.

## Preparação (offline, já permitida ao desenvolvedor)
Validar o projeto candidato, sem alterar o repositório GitHub:
```bash
python -m pytest -q -p no:cacheprovider tests/test_p0_gha_prep.py
sha256sum reference/03-postgres-integration.original.yml
sha256sum reference/requirements-test.B39.lock.txt
```
A suíte offline usa fixtures artificiais para testar rejeições; não demonstra compatibilidade real do wheelhouse no Python 3.12.

## Execução futura do workflow: comandos EXATOS, **NÃO EXECUTAR AINDA**
O arquivo precisa existir na branch padrão para o GitHub aceitar `workflow_dispatch`. Exige parecer AO-01 específico e autorização humana separada para eventual bootstrap na `main`.
Depois desses gates (inclusive **registrar variável `EFATA_P0_GHA05_APPROVED_SHA` após aprovação AO-01 do SHA completo**) e SOMENTE depois, o executor poderá utilizar no GitHub CLI:
```bash
APPROVED_SHA="<SHA_40_HEX_APROVADO_AO01>"
gh workflow run 05-p0-provenance-prep.yml \
  --repo patroaiconsultech/efata-777-backend-premium-final-20260917 \
  --ref ensaio/p0-schema-colaboracao-20261017 \
  -f approval_phrase=P0_PROVENIENCIA_SOMENTE \
  -f approved_sha="$APPROVED_SHA"
```
O texto do input é somente barreira operacional: NÃO substitui aprovação AO-01.

## Sequência interna que a execução autorizada realizará (SEM DB)
1. Valida evento, branch, consentimento, arquitetura e igualdade SHA **em quatro lugares**: repo var, input, evento GitHub e checkout real. Variável não configurada => HOLD.
2. Checkout somente do repo em SHA resolvido pelo runner, sem persistir credenciais.
3. Confirma SHA-256 do lock B39 e versão Python 3.12 no Linux/amd64.
4. Faz, para cada tag allowlistada, SOMENTE consulta ao Docker Hub OCI:
```bash
docker buildx imagetools inspect --raw docker.io/library/postgres:18.6 > postgres.oci-manifest.json
docker buildx imagetools inspect --raw docker.io/library/python:3.12-slim-bookworm > python_base.oci-manifest.json
```
Os JSONs são validados por script, SHA256 derivado dos bytes brutos, plataforma linux/amd64, e cada `repo@sha256:<64hex>` é consultado novamente com `docker buildx imagetools inspect`. Nenhum container inicia.
5. Faz `pip download` somente de **wheels** com hash obrigatório a partir de `requirements-test.lock.txt` (PyPI público).
6. Verifica localmente todos os wheels por hash, nome, versão e **tags combinadas** do interpretador real com `packaging.tags.sys_tags()`. Exige também conjunto completo de dependências **aplicáveis**, avaliado via marcadores PEP 508 (B39: 71 entradas, 69 aplicáveis no Linux CPython 3.12). Um wheel faltante, extra ou ABI incompatível gera HOLD.
7. Cria venv descartável em `RUNNER_TEMP`, usa `pip install --no-index --require-hashes --only-binary`, executa `pip check` e registra freeze.
8. Faz hash SHA256 de todos os arquivos do artefato e grava `run_id`, `run_attempt`, SHA/branch, plataforma, sem credenciais.
9. Faz upload do artefato mesmo se etapa falhar.

## Proibição operacional
- Não modificar o workflow 03; não disparar push/main nem PR para experimentar.
- Não publicar `DATABASE_URL`, segredos Railway ou token em logs.
- Não adicionar jobs `services: postgres`, `alembic`, DDL, `docker run`, `docker compose` ou `psql`.
- `python:3.12-slim-bookworm` é apenas BASE candidata, **não** imagem final qualificada com `pg_dump 18.6`. Seleção/qualificação da imagem completa requer gate posterior.
- Falha em resolver wheel/hash/digest => HOLD, não instalar fontes ou omitir dependências.
- A imagem PostgreSQL capturada não foi iniciada nem validada em runtime.
- Runner e Python microversões ainda não são imutáveis; capturar metadados e não exagerar reprodutibilidade.

## Evidências a entregar ao AO-01 após execução futura autorizada
- Link do GitHub run, run ID/attempt/commit SHA, branch e actor verificados na interface.
- `run-metadata.txt`, `b39-lock-sha256.txt`, `python-version.txt`, `pip-version.txt`, `buildx-version.txt`, SHA completo aprovado verificado no GitHub e checkout.
- Para cada imagem candidata: manifest JSON bruto, SHA, relatório OCI, pin/ref e saída de reconsulta pinned.
- `wheelhouse-proof.json`, wheelhouse real, `offline-pip-check.txt`, `offline-installed-freeze.txt`.
- `SHA256SUMS.txt` gerado no runner, mais hash do artefato GitHub baixado.
- Resultado por etapa: `DIGESTS_CAPTURED`, `WHEELS_VALIDATED`, `OFFLINE_INSTALL`, independentes.
- Estado final do qualificador: **NÃO_APROVADO** até prova de imagem com `pg_dump 18.6` e autorização distinta para o PostgreSQL descartável.

## ROLLBACK
Antes da publicação: nenhuma ação externa; descartar pasta.
Se novo workflow for futuramente autorizado e publicado, revertê-lo por commit isolado e manter o workflow 03 sem mudanças.
Em falha, reter artefatos; não tentar migrar nem repetir sobre DB parcialmente escrito (este estágio não escreve em DB).

**Nota crítica de bootstrap:** publicar qualquer commit em `main`, até somente `.github/workflows/05-p0-provenance-prep.yml`, pode acionar CI e auto-deploy Railway. Não há autorização neste gate; ver plano separado. **ROOT_CAUSE_P0_PRODUTIVA não é alterada por este trabalho de proveniência.**
