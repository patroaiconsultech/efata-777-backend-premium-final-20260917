# Plataforma Efata 777 — Matriz de variáveis de ambiente

> Documento operacional para o release premium. **Nenhum valor secreto real deve ser colocado neste arquivo, no GitHub, em ZIPs ou no frontend.** Segredos devem ser inseridos diretamente no Railway ou em um secret manager.

## 1. Política de ambientes

| Ambiente | `PLATFORM_ENVIRONMENT` | Autenticação | Banco | Storage | Dados reais | Observação |
|---|---|---|---|---|---|---|
| Desenvolvimento | `development` | `external_required` ou stub local controlado | SQLite ou PostgreSQL local | `local` | Não | Nunca usar como prova de produção |
| Testes | `test` | `test` | SQLite descartável | `local` | Não | Somente CI e fixtures sintéticos |
| Staging | `staging` | OIDC real com introspection | PostgreSQL descartável/staging | S3-compatible | Não | Gate obrigatório antes de produção |
| Produção | `production` | OIDC/ZITADEL real | PostgreSQL Railway com TLS | S3-compatible com SSE | Sim | Requer release SHA, secrets explícitos e rollback |

A autenticação **first-party permanece fora deste release**. O pacote premium recomendado mantém OIDC/ZITADEL como autoridade de identidade.

## 2. Backend — variáveis obrigatórias em staging e produção

| Variável | Produção | Tipo | Segredo | Valor-modelo / regra |
|---|---:|---|---:|---|
| `PLATFORM_ENVIRONMENT` | Sim | enum | Não | `production` |
| `PLATFORM_RELEASE_SHA` | Sim | SHA | Não | SHA exato do commit promovido; não usar `local`, `unknown` ou `dev` |
| `DATABASE_URL` | Sim | URL | Sim | PostgreSQL com `sslmode=require`; nunca commitar |
| `PLATFORM_ALLOWED_ORIGINS` | Sim | lista separada por espaço | Não | `https://plataforma-efata-777-frontend-production.up.railway.app` |
| `PLATFORM_AUTH_MODE` | Sim | enum | Não | `oidc_introspection` para o contrato fail-closed do backend |
| `PLATFORM_OIDC_ISSUER` | Sim | URL | Não | `https://orkio-efata777-gtaskz.us1.zitadel.cloud` |
| `PLATFORM_OIDC_AUDIENCE` | Sim | string | Não | Audience configurada no projeto OIDC |
| `PLATFORM_OIDC_INTROSPECTION_ENDPOINT` | Sim | URL HTTPS | Não | Endpoint de introspection do provedor |
| `PLATFORM_OIDC_INTROSPECTION_CLIENT_ID` | Sim | string | Não | Client ID de introspection |
| `PLATFORM_OIDC_INTROSPECTION_CLIENT_SECRET` | Sim | string | Sim | Secret OIDC; somente Railway |
| `PLATFORM_OIDC_USER_CLAIM` | Recomendado | string | Não | `sub` |
| `PLATFORM_OIDC_TENANT_CLAIM` | Recomendado | string | Não | `urn:zitadel:iam:user:resourceowner:id` |
| `PLATFORM_OIDC_ROLES_CLAIM` | Recomendado | string | Não | `urn:zitadel:iam:org:project:roles` |
| `PLATFORM_ADMIN_EMAIL_ALLOWLIST` | Sim | e-mails CSV | Não | `patroaiconsultech@gmail.com,daniel@patroai.com` |
| `PLATFORM_INVITATION_TOKEN_SECRET` | Sim | string aleatória | Sim | Pelo menos 32 caracteres; nunca usar o default de desenvolvimento |
| `PLATFORM_INVITATION_TTL_HOURS` | Recomendado | inteiro | Não | `72` |
| `PLATFORM_INVITATION_BASE_URL` | Sim | URL | Não | `https://plataforma-efata-777-frontend-production.up.railway.app/invite` |
| `PLATFORM_DEMO_IDENTITY_HEADERS_ENABLED` | Sim | boolean | Não | `false` |
| `PLATFORM_OWNER_SUBJECT` | Opcional | subject | Não | Usar somente se o contrato de owner exigir |

## 3. Backend — banco, storage e continuidade

| Variável | Quando usar | Regra |
|---|---|---|
| `PLATFORM_ARTIFACTS_ENABLED` | `true` em produção se documentos estiverem ativos | Requer storage durável |
| `PLATFORM_ARTIFACT_STORAGE_BACKEND` | `s3` em staging/produção | `local` somente development/test |
| `PLATFORM_ARTIFACT_STORAGE_BUCKET` | S3 | Bucket dedicado por ambiente |
| `PLATFORM_ARTIFACT_STORAGE_REGION` | S3 | Região do bucket |
| `PLATFORM_ARTIFACT_STORAGE_ENDPOINT_URL` | S3-compatible | HTTPS; vazio para AWS S3 nativo |
| `PLATFORM_ARTIFACT_STORAGE_ACCESS_KEY_ID` | S3 | Secret; nunca commitar |
| `PLATFORM_ARTIFACT_STORAGE_SECRET_ACCESS_KEY` | S3 | Secret; nunca commitar |
| `PLATFORM_ARTIFACT_STORAGE_SSE` | S3 | `AES256` ou `aws:kms` |
| `PLATFORM_ARTIFACT_STORAGE_KMS_KEY_ID` | SSE-KMS | Obrigatório quando SSE=`aws:kms` |
| `PLATFORM_ARTIFACT_STORAGE_PREFIX` | S3 | Prefixo sem `..`, por exemplo `efata/production` |
| `PLATFORM_ARTIFACT_STORAGE_PATH` | Local | `./data/artifacts`; não usar para produção |
| `PLATFORM_MAX_UPLOAD_BYTES` | Upload | Modelo: `10000000` |
| `PLATFORM_DOCUMENT_CONTEXT_ENABLED` | Documentos | `true` |
| `PLATFORM_DOCUMENT_CONTEXT_MAX_FILES` | Documentos | Modelo: `6` |
| `PLATFORM_DOCUMENT_CONTEXT_MAX_CHARS` | Documentos | Modelo: `48000` |
| `PLATFORM_DOCUMENT_CONTEXT_MAX_CHARS_PER_FILE` | Documentos | Modelo: `20000` |
| `PLATFORM_DOCUMENT_CONTEXT_MAX_PDF_PAGES` | Documentos | Modelo: `40` |
| `PLATFORM_DOCUMENT_INGESTION_MAX_ARCHIVE_ENTRIES` | DOCX/PPTX/XLSX | Modelo: `512` |
| `PLATFORM_DOCUMENT_INGESTION_MAX_TOTAL_UNCOMPRESSED_BYTES` | DOCX/PPTX/XLSX | Modelo: `64000000` |
| `PLATFORM_DOCUMENT_INGESTION_MAX_MEMBER_BYTES` | DOCX/PPTX/XLSX | Modelo: `16000000` |
| `PLATFORM_DOCUMENT_INGESTION_DOCX_MAX_XML_BYTES` | DOCX/XML | Modelo: `2000000` |

O storage de produção deve usar TLS, bucket privado, criptografia em repouso, lifecycle/retention, versionamento quando disponível e política de menor privilégio. O banco deve ter backup automatizado e um ensaio de restore documentado.

## 4. Backend — LLM, voz, Realtime e limites

| Variável | Uso | Valor-modelo / regra |
|---|---|---|
| `PLATFORM_LLM_PRIMARY_PROVIDER` | Provider principal | `openai`, `anthropic` ou `google` |
| `PLATFORM_LLM_HTTP_TIMEOUT_SECONDS` | Timeout LLM | Maior que zero; modelo `30` |
| `PLATFORM_LLM_PROVIDER_FAILOVER_ENABLED` | Failover | `false` até haver governança multi-provider validada |
| `PLATFORM_LLM_AUTO_ROUTE_ENABLED` | Auto route | `false` até haver governança validada |
| `OPENAI_API_KEY` | OpenAI | Secret Railway |
| `OPENAI_DEFAULT_MODEL` | OpenAI | Modelo aprovado no ambiente |
| `OPENAI_API_BASE` | OpenAI compatível | URL HTTPS opcional |
| `ANTHROPIC_API_KEY` | Anthropic | Secret Railway |
| `ANTHROPIC_DEFAULT_MODEL` | Anthropic | Modelo aprovado |
| `ANTHROPIC_API_BASE` | Anthropic | `https://api.anthropic.com/v1` |
| `ANTHROPIC_MAX_TOKENS` | Anthropic | Modelo `4096` |
| `GEMINI_API_KEY` ou `GOOGLE_API_KEY` | Google | Secret Railway |
| `GOOGLE_DEFAULT_MODEL` | Google | Modelo aprovado |
| `GOOGLE_API_BASE` | Google | URL HTTPS oficial |
| `GOOGLE_MAX_OUTPUT_TOKENS` | Google | Modelo `4096` |
| `PLATFORM_REALTIME_STREAMING_ENABLED` | Realtime | `true` |
| `PLATFORM_REALTIME_BRIDGE_ENABLED` | Ponte Realtime | Somente se o bridge estiver configurado |
| `PLATFORM_REALTIME_TRANSCRIPTION_MODEL` | Transcrição | Modelo aprovado |
| `PLATFORM_REALTIME_VOICE_ENABLED` | Voz | `true` somente com provider configurado |
| `PLATFORM_VOICE_PROVIDER` | Voz | Provider permitido; não usar `disabled` quando voice estiver ativo |
| `PLATFORM_VOICE_BINDINGS_JSON` | Voz | JSON sem segredos, validado e versionado fora do código sensível |
| `PLATFORM_TTS_ENABLED` | TTS | `true` somente com provider ativo |
| `PLATFORM_TTS_PROVIDER` | TTS | `openai` ou `disabled` |
| `PLATFORM_TTS_HTTP_TIMEOUT_SECONDS` | TTS | Modelo `20` |
| `PLATFORM_TTS_MAX_CHARS` | TTS | Até `4096` |
| `PLATFORM_TTS_USER_RATE_LIMIT_PER_MINUTE` | TTS | Modelo `12` |
| `PLATFORM_TTS_TENANT_RATE_LIMIT_PER_MINUTE` | TTS | Modelo `60` |
| `PLATFORM_TTS_MESSAGE_RATE_LIMIT_PER_MINUTE` | TTS | Modelo `4` |
| `PLATFORM_TTS_CACHE_ENABLED` | Cache TTS | `true` somente em storage permitido |
| `PLATFORM_TTS_CACHE_PATH` | Cache local | Path gravável; em produção preferir storage durável ou cache efêmero explicitamente aceito |
| `PLATFORM_STT_ENABLED` | STT | `true` somente com modelo prewarmed |
| `PLATFORM_STT_PROVIDER` | STT | `faster_whisper` ou `disabled` |
| `PLATFORM_STT_MODEL` | STT | Modelo aprovado |
| `PLATFORM_STT_DEVICE` | STT | `cpu`, `cuda` ou `auto` |
| `PLATFORM_STT_COMPUTE_TYPE` | STT | Modelo `int8` |
| `PLATFORM_STT_MAX_UPLOAD_BYTES` | STT | Modelo `8000000` |
| `PLATFORM_STT_ALLOWED_LANGUAGES` | STT | `pt,en,es` |
| `PLATFORM_STT_MODEL_CACHE_DIR` | STT | `/opt/orkio/models/faster-whisper` |
| `PLATFORM_STT_LOCAL_FILES_ONLY` | STT | `true` em produção com prewarm concluído |
| `PLATFORM_STT_TIMEOUT_SECONDS` | STT | Maior que zero quando STT está ativo |
| `PLATFORM_STT_CONCURRENCY_LIMIT` | STT | Maior que zero quando STT está ativo |
| `PLATFORM_INTERNAL_AGENT_CONSULTATION_ENABLED` | Governança | `true` somente após validar allowlist e limites |
| `PLATFORM_INTERNAL_AGENT_CONSULTATION_MAX` | Governança | Modelo `2` |
| `PLATFORM_FOUNDER_COUNCIL_ENABLED` | Governança | `false` por default |
| `PLATFORM_FOUNDER_COUNCIL_MIN_CONFIGURED_PROVIDERS` | Governança | Mínimo `2` |

## 5. Backend — GitHub, leitura externa e ferramentas

| Variável | Uso | Regra |
|---|---|---|
| `PLATFORM_GITHUB_INTEGRATION_ENABLED` | Auditoria de código | `true` somente quando configurado |
| `PLATFORM_GITHUB_READ_ONLY` | GitHub | Obrigatoriamente `true` |
| `PLATFORM_GITHUB_ALLOWED_REPOSITORIES` | GitHub | Lista explícita de `owner/repo`; sem wildcard |
| `PLATFORM_GITHUB_API_BASE` | GitHub | `https://api.github.com` |
| `PLATFORM_GITHUB_READ_TOKEN` | GitHub | Secret read-only com menor escopo |
| `PLATFORM_GITHUB_HTTP_TIMEOUT_SECONDS` | GitHub | Modelo `5` |
| `PLATFORM_GITHUB_MAX_FILE_BYTES` | GitHub | Modelo `250000` |
| `PLATFORM_GITHUB_MAX_TREE_ENTRIES` | GitHub | Modelo `5000` |
| `PLATFORM_GITHUB_SNAPSHOT_MAX_FILES` | GitHub | Modelo `8` |
| `PLATFORM_GITHUB_SNAPSHOT_MAX_CHARS` | GitHub | Modelo `60000` |
| `PLATFORM_EXTERNAL_READ_ENABLED` | Leitura externa | `false` até allowlist/egress serem validados |
| `PLATFORM_EXTERNAL_READ_ALLOWED_DOMAINS` | Leitura externa | Domínios explícitos |
| `PLATFORM_EXTERNAL_READ_MAX_BYTES` | Leitura externa | Limite de resposta |
| `PLATFORM_EXTERNAL_READ_MAX_URLS_PER_TURN` | Leitura externa | Limite por turno |
| `PLATFORM_EXTERNAL_READ_TIMEOUT_SECONDS` | Leitura externa | Timeout positivo |
| `PLATFORM_PYTHON_TOOL_ENABLED` | Execução Python | `false` em produção até sandbox real ser validada |
| `PLATFORM_PYTHON_TOOL_MAX_CODE_BYTES` | Python tool | Limite de código |
| `PLATFORM_PYTHON_TOOL_MAX_OUTPUT_BYTES` | Python tool | Limite de saída |
| `PLATFORM_PYTHON_TOOL_TIMEOUT_SECONDS` | Python tool | Timeout curto |

## 6. Backend — access gate e evolução assistida

| Variável | Produção recomendada | Regra |
|---|---|---|
| `PLATFORM_ACCESS_GATE_ENABLED` | Conforme onboarding | `true` quando convite/código estiver ativo |
| `PLATFORM_ACCESS_GATE_CODE_HASHES` | Secret derivado | Hashes SHA-256, nunca códigos em claro |
| `PLATFORM_ACCESS_GATE_SIGNING_SECRET` | Secret | Pelo menos 32 caracteres |
| `PLATFORM_ACCESS_GATE_TENANT_ID` | Tenant existente | Obrigatório em produção quando gate ativo |
| `PLATFORM_ACCESS_GATE_TTL_SECONDS` | `600` | Entre 60 e 3600 |
| `PLATFORM_ASSISTED_EVOLUTION_ENABLED` | `false` | Só habilitar com governança aprovada |
| `PLATFORM_EVOLUTION_EXECUTION_ALLOWED` | `false` | O código rejeita autoexecução por design |
| `PLATFORM_EVOLUTION_HUMAN_APPROVAL_REQUIRED` | `true` | Manter sempre em produção |

## 7. Frontend — build/runtime público

O frontend é uma SPA e **não pode receber secrets**. Apenas as variáveis públicas abaixo podem ser injetadas pelo `public-config.js`/`server.mjs`.

| Variável | Produção modelo | Observação |
|---|---|---|
| `PORT` | `8080` | Porta do servidor estático Railway |
| `NODE_ENV` | `production` | Runtime do servidor |
| `VITE_API_BASE_URL` | `https://plataforma-efata-777-backend-production.up.railway.app` | URL pública do backend |
| `VITE_STREAM_TIMEOUT_MS` | `300000` | Timeout de stream em milissegundos |
| `VITE_OIDC_AUTHORIZATION_ENDPOINT` | `https://orkio-efata777-gtaskz.us1.zitadel.cloud/oauth/v2/authorize` | Público |
| `VITE_OIDC_TOKEN_ENDPOINT` | `https://orkio-efata777-gtaskz.us1.zitadel.cloud/oauth/v2/token` | Público; não é client secret |
| `VITE_OIDC_END_SESSION_ENDPOINT` | `https://orkio-efata777-gtaskz.us1.zitadel.cloud/oidc/v1/end_session` | Público |
| `VITE_OIDC_CLIENT_ID` | `<client-id-publico>` | Client público de SPA |
| `VITE_OIDC_REDIRECT_URI` | `https://plataforma-efata-777-frontend-production.up.railway.app/auth/callback` | Deve estar cadastrado no IdP |
| `VITE_OIDC_POST_LOGOUT_REDIRECT_URI` | `https://plataforma-efata-777-frontend-production.up.railway.app` | Deve estar cadastrado no IdP |
| `VITE_OIDC_SCOPE` | `openid profile email urn:zitadel:iam:user:resourceowner urn:zitadel:iam:org:project:id:385220733510354436:aud urn:zitadel:iam:org:projects:roles` | Sem client secret |
| `VITE_OIDC_AUDIENCE` | `<audience-publica-ou-vazio>` | Conforme o provider |
| `ORKIO_CSP_CONNECT_SRC` | `<backend> <oidc> <origens-aprovadas>` | Lista separada por espaço; sem wildcard |

Nunca colocar no frontend: `DATABASE_URL`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `PLATFORM_OIDC_INTROSPECTION_CLIENT_SECRET`, `PLATFORM_INVITATION_TOKEN_SECRET`, `PLATFORM_GITHUB_READ_TOKEN`, credenciais S3, SMTP ou qualquer JWT signing secret.

## 8. Checklist Railway antes do staging

1. Criar secrets diretamente no Railway e verificar que nenhum aparece em logs, variáveis públicas ou imagens.
2. Configurar `PLATFORM_ENVIRONMENT=staging`, `PLATFORM_RELEASE_SHA` com o SHA real do commit e `PLATFORM_AUTH_MODE=oidc_introspection`.
3. Usar PostgreSQL staging com TLS, aplicar `alembic upgrade head` e capturar `health`/`ready`.
4. Configurar bucket staging privado com SSE e testar upload, leitura, download e cleanup.
5. Configurar OIDC real, redirect/callback e introspection client.
6. Executar smoke autenticado, cinco turnos Realtime, documentos e logout.
7. Testar backup/restore e rollback da imagem anterior.
8. Somente após todos os gates, promover o mesmo SHA para produção.

## 9. Referências operacionais

A lista autorizada do frontend é a constante `PUBLIC_CONFIG_KEYS` em `public-config.js`. A lista do backend é derivada dos aliases de `Settings` em `src/orkio_v2/config.py`. Se uma nova variável for criada, ela deve ser adicionada a estes contratos, documentada, testada e classificada como pública ou secreta antes de ser usada.
