# EFATÀ 777 — Plano de bootstrap manual do workflow 05 (NÃO EXECUTAR)

## Problema operacional confirmado
`workflow_dispatch` requer que o arquivo workflow esteja na branch padrão do repositório GitHub, embora permita executar o conteúdo selecionado via `--ref` em outra branch. Documentação oficial: https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow

A branch de ensaio `ensaio/p0-schema-colaboracao-20261017` **não** deve ser mesclada em `main`.
O CI PG16 `03-postgres-integration.yml` deve permanecer byte-a-byte idêntico.

## Fase A — preparação off-platform, já coberta pelo GO atual
- Revisar patch e testes offline. NÃO subir GitHub, NÃO executar workflow.
- Rejeitar qualquer SHA `ac2e754` abreviado como gate: o aprovado precisa ser um hash Git completo de 40 hex, obtido *após* um commit autorizado.
- O YAML 05 fica somente no pacote de proposta até GO AO-01 específico para commit branch.

## Fase B — branch de ensaio, gate separado, NÃO EXECUTAR AGORA
**Pré-condição:** parecer AO-01 para diff exato, autorização humana para commit e push; confirmar se a branch já tem PR e se push nela dispara automações.
- Com checkout limpo da branch, criar **somente** novos arquivos do workflow 05 e scripts documentados; nunca modificar 03.
- Capturar diff e árvore antes do commit, depois SHA completo:
```bash
git rev-parse HEAD
git diff --stat main...HEAD
git diff -- .github/workflows/03-postgres-integration.yml
```
- Verificar o commit novo no GitHub por fonte independente, não confiar só no Git local.
- AO-01 revisa o SHA completo S e aprova ou rejeita; **não** registrar como aprovado antes do aceite.

## Fase C — registro de SHA aprovado, gate de settings separado, NÃO EXECUTAR AGORA
- Com aprovação expressa, um operador autorizado registra variável **de repositório** (não token/secret):
`EFATA_P0_GHA05_APPROVED_SHA=S`
- Audit log / captura da variável e revisão do acesso de alteração; se a variável estiver ausente ou não for SHA de 40 hex, o job falha.
- O input manual `approved_sha` e o evento `GITHUB_SHA` precisam ser exatamente S. Verifica `git rev-parse HEAD` após o checkout.
- Se o commit da branch mudar, revogar/atualizar o SHA somente após nova auditoria.

## Fase D — decisão sobre execução manual, gate independente, NÃO EXECUTAR AGORA
**Opção 1 (exige controle maior):** bootstrap isolado da **cópia de `.github/workflows/05-p0-provenance-prep.yml`** na `main`, sem merge da branch e sem incluir scripts P0 na `main`. Na execução com `--ref` apontando para branch ensaio, os scripts são obtidos daquele commit S; a branch/HEAD ainda são guardados.
- Este push na `main` pode disparar **CI automático e auto-deploy Railway**. Logo, **NO-GO enquanto não houver aprovação para mitigar/verificar o risco de deploy, independentemente do conteúdo do diff**. Não se deve pressupor que workflow-only commit não dispara deploy.
- Requer gate isolado para commit main, publicação, configuração de variável e execução. Mesmo após bootstrap, publicação NÃO autoriza run.
- Verificar no GitHub `main` que o diff exato mudou **somente** o arquivo 05 e nenhum dos 4 workflows originais.
- Se a governança não autorizar o risco de main, não usar este caminho.

**Opção 2 (sem push em main):** submeter um ambiente de computação temporário separado (por exemplo, ambiente de desenvolvimento na nuvem isolado, sem credenciais Railway) como nova proposta técnica AO-01. Isso **não** é execução GitHub Actions nem qualifica automaticamente o PostgreSQL. Requer gate e revisão de custos/isolamento próprios.

## Exemplo de comando FUTURO para auditoria (NÃO EXECUTAR)
Somente após gates A→D, no repositório autorizado:
```bash
APPROVED_SHA='<SHA_EXATO_40_HEX_APROVADO_PELO_AO01>'
gh workflow run 05-p0-provenance-prep.yml \
  --repo patroaiconsultech/efata-777-backend-premium-final-20260917 \
  --ref ensaio/p0-schema-colaboracao-20261017 \
  -f approval_phrase=P0_PROVENIENCIA_SOMENTE \
  -f approved_sha="$APPROVED_SHA"
```
Sem variável repo `EFATA_P0_GHA05_APPROVED_SHA` idêntica, falha; sem aprovação humana do run, proibido.

## Coleta futura de evidência
`run_id`, `run_attempt`, repo, branch, `GITHUB_SHA`, SHA do checkout, validade repo var, runner OS/ARCH, hash do lock, bytes OCI e digest `@sha256`, wheelhouse (69 candidatos aplicáveis esperados para o lock B39), tags completas, hashes e relatório de instalação offline/pip check.
Se falha, publicar somente evidências sanitizadas e preservar logs sem divulgar segredos.

## Rollback
Antes da publicação: apagar arquivos de proposta.
Após futuro commit branch: revert exclusivamente do commit autorizado, preservando histórico do gate.
Após futuro bootstrap main: revert exclusivamente da adição do workflow 05, com autorização humana; **reverter na main pode disparar novamente CI/deploy**, portanto também exige gate de produção independente.
