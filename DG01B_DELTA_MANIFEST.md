# DG01B DELTA MANIFEST — BACKEND R3

AGENT=DG-01B
PACKAGE_REVISION=R3
BASE_REPOSITORY=patroaiconsultech/efata-777-backend-premium-final-20260917
BASE_BRANCH=main (archive wrapper/artifact declaration; remote branch not independently verified)
BASE_HEAD_SHA=NOT_PROVEN
BASE_TREE_SHA=NOT_PROVEN
BASELINE_ARCHIVE_SHA256=56f1d245ad64452b4858f9386044c26c429730fb5ce7682cd0019db5f8fc1613
PARENT_DG01B_BACKEND_R2_SHA256=02b4a8421d815c7922c03715b3723e65113fc3b5ac6eff3d2bd576349eee92ad
SEPARATE_SK_DIRECT_001_PACKAGE_SHA256=f7171497d448440f73b112913bba58d5eada1366aa1b1c617143bde7d5f05910
SK_DIRECT_001_INCLUDED=NO
PACKAGE_CREATED_AT=2026-10-02T19:17:38Z

## Delta summary

ADDED=NONE
MODIFIED=23
DELETED=NONE
UNCHANGED_NOT_INCLUDED=YES
MIGRATIONS_INCLUDED=NONE
R3_SPECIFIC_CHANGED_PATHS=src/orkio_v2/services/document_context.py; tests/test_document_context.py
TESTS_ADDED_OR_CHANGED=tests/test_artifact_runtime_context_r04p3.py, tests/test_billing_asaas.py, tests/test_blob_storage.py, tests/test_document_context.py, tests/test_hyper_cocreator.py, tests/test_internal_consultation_governance.py, tests/test_knowledge_plane.py, tests/test_premium_capability_plane.py
KNOWN_LIMITATIONS=Remote GitHub HEAD/tree, PostgreSQL-specific skipped gates, live LLM, post-R3 Railway runtime and Cloudflare R2 document extraction smoke remain not independently proven by this package.
CROSS_WORKSTREAM_DEPENDENCIES=PATROAI_PLATFORM remains owned by DG-01A; SK-DIRECT-001 is a separate candidate and is not included in this package.
ROLLBACK=For DOCUMENT-R2-001 only, restore document_context.py and test_document_context.py from parent R2. For full DG01B rollback, restore all MODIFIED paths from the exact Premium baseline archive. No database downgrade required.
APPLY_ORDER=docs/EFATA_PREMIUM_ENVIRONMENT_VARIABLES.md; src/orkio_v2/billing/routes.py; src/orkio_v2/config.py; src/orkio_v2/main.py; src/orkio_v2/routes.py; src/orkio_v2/services/artifact_context.py; src/orkio_v2/services/blob_storage.py; src/orkio_v2/services/document_context.py; src/orkio_v2/services/external_read_tool.py; src/orkio_v2/services/hyper_cocreator.py; src/orkio_v2/services/internal_consultation.py; src/orkio_v2/services/knowledge_retrieval.py; src/orkio_v2/services/python_runtime/contracts.py; src/orkio_v2/services/python_tool.py; src/orkio_v2/services/realtime_execution.py; tests/test_artifact_runtime_context_r04p3.py; tests/test_billing_asaas.py; tests/test_blob_storage.py; tests/test_document_context.py; tests/test_hyper_cocreator.py; tests/test_internal_consultation_governance.py; tests/test_knowledge_plane.py; tests/test_premium_capability_plane.py

## R3 causal finding

GAP=DOCUMENT-R2-001
EXPECTED=An attachment written through configured BlobStorage can be read by Document Context through the same configured storage backend, including S3-compatible Cloudflare R2.
OBSERVED_RUNTIME=Attachment POST returned HTTP 200, then Document Context logged DOCUMENT_STORAGE_MISSING for the same Markdown attachment.
OBSERVED_SOURCE=build_document_context() built configured BlobStorage for manifests/selective reads but legacy fallback bypassed it with local Path.read_bytes().
ROOT_CAUSE_STATUS=CONFIRMED_IN_RUNTIME_LOG_AND_SOURCE
MINIMUM_PATCH=Replace the legacy local filesystem fallback read with storage.get(attachment.storage_key); preserve DOCUMENT_STORAGE_MISSING for BLOB_NOT_FOUND and DOCUMENT_STORAGE_PATH_INVALID for invalid keys; map other BlobStorageError values to DOCUMENT_STORAGE_ERROR; preserve SHA-256 validation and extraction policy.
RUNTIME_PROOF_AFTER_PATCH=NOT_PROVEN; requires controlled upload + context extraction smoke after independent review.

## R3 parent binding

R2_DOCUMENT_CONTEXT_SHA256=d2d6051f12e6301fe3a758d3419b32a183cb5c7edde51c309f8d73a029f2b16c
R3_DOCUMENT_CONTEXT_SHA256=6cb9061f8725a38fc0efd23f86c8d70b8be4a7224fd8824cc405ff7f7bd9df61
R2_TEST_DOCUMENT_CONTEXT_SHA256=623d286cc9a9ed4ded3aa100ea0767727a9d8a39df5801215b22df1b31418ebf
R3_TEST_DOCUMENT_CONTEXT_SHA256=987d8eec9baf87f632a48d23ae4cae3b57e674402332749f7c30de6ec75a1f6b

## Cross-workstream boundary

CROSS_WORKSTREAM_DEPENDENCY
OWNER=DG-01A
COMPONENT=PATROAI_PLATFORM / Platform Self-Knowledge authority
REQUIRED_CHANGE=No change by DG-01B R3.
WHY=DOCUMENT-R2-001 is storage retrieval plumbing and does not alter Self-Knowledge authority or Thread ACL.
BLOCKING=NO for DOCUMENT-R2-001; separate review remains required for PATROAI_PLATFORM.

SEPARATE_CANDIDATE
OWNER=DG-01A
COMPONENT=SK-DIRECT-001 natural Self-Knowledge GitHub intent detection
INCLUDED=NO
WHY=User requested DG-01B to proceed only with its own document/R2 front; composition must be audited separately.

## Files

PATH=docs/EFATA_PREMIUM_ENVIRONMENT_VARIABLES.md
STATUS=MODIFIED
PURPOSE=Document provider-managed S3 encryption mode for S3-compatible providers such as Cloudflare R2.
RELATED_GAP=ARTIFACT-R2-001
RISK=LOW
TEST_COVERAGE=N/A (documentation)

PATH=src/orkio_v2/billing/routes.py
STATUS=MODIFIED
PURPOSE=Bound Asaas webhook request bodies before JSON/domain processing.
RELATED_GAP=BILL-002
RISK=MEDIUM
TEST_COVERAGE=tests/test_billing_asaas.py

PATH=src/orkio_v2/config.py
STATUS=MODIFIED
PURPOSE=Preserve DG01B webhook body-limit config and provider-managed S3 encryption mode.
RELATED_GAP=BILL-002 / ARTIFACT-R2-001
RISK=LOW
TEST_COVERAGE=tests/test_billing_asaas.py; tests/test_blob_storage.py

PATH=src/orkio_v2/main.py
STATUS=MODIFIED
PURPOSE=Narrowly exempt the provider webhook path from browser CSRF while preserving provider authentication.
RELATED_GAP=BILL-001
RISK=MEDIUM
TEST_COVERAGE=tests/test_billing_asaas.py

PATH=src/orkio_v2/routes.py
STATUS=MODIFIED
PURPOSE=Inject user-controlled Hyper profile context separately from system policy in HTTP/SSE execution assembly.
RELATED_GAP=AGENT-001
RISK=MEDIUM
TEST_COVERAGE=tests/test_hyper_cocreator.py + full regression

PATH=src/orkio_v2/services/artifact_context.py
STATUS=MODIFIED
PURPOSE=Keep persisted artifact metadata as data rather than system authority.
RELATED_GAP=ART-001
RISK=LOW
TEST_COVERAGE=tests/test_artifact_runtime_context_r04p3.py

PATH=src/orkio_v2/services/blob_storage.py
STATUS=MODIFIED
PURPOSE=Support provider-managed encryption mode without AWS SSE headers while preserving AES256/aws:kms.
RELATED_GAP=ARTIFACT-R2-001
RISK=MEDIUM
TEST_COVERAGE=tests/test_blob_storage.py

PATH=src/orkio_v2/services/document_context.py
STATUS=MODIFIED
PURPOSE=Keep attachment content as untrusted user-role data and read legacy attachment bytes through configured BlobStorage instead of local filesystem.
RELATED_GAP=KNOW-001 / DOCUMENT-R2-001
RISK=MEDIUM
TEST_COVERAGE=tests/test_document_context.py

PATH=src/orkio_v2/services/external_read_tool.py
STATUS=MODIFIED
PURPOSE=Keep fetched external content as untrusted user-role data.
RELATED_GAP=WEB-001
RISK=MEDIUM
TEST_COVERAGE=tests/test_premium_capability_plane.py

PATH=src/orkio_v2/services/hyper_cocreator.py
STATUS=MODIFIED
PURPOSE=Separate static Hyper system policy from user-controlled name/onboarding-goal data.
RELATED_GAP=AGENT-001
RISK=MEDIUM
TEST_COVERAGE=tests/test_hyper_cocreator.py

PATH=src/orkio_v2/services/internal_consultation.py
STATUS=MODIFIED
PURPOSE=Prevent specialist LLM output from being promoted to system authority.
RELATED_GAP=AGENT-003
RISK=MEDIUM
TEST_COVERAGE=tests/test_internal_consultation_governance.py

PATH=src/orkio_v2/services/knowledge_retrieval.py
STATUS=MODIFIED
PURPOSE=Demote mutable institutional/agent/personal Knowledge layers to user-role data while preserving PATROAI_PLATFORM boundary.
RELATED_GAP=KNOW-002
RISK=MEDIUM
TEST_COVERAGE=tests/test_knowledge_plane.py

PATH=src/orkio_v2/services/python_runtime/contracts.py
STATUS=MODIFIED
PURPOSE=Keep Python runtime stdout/stderr as untrusted tool data.
RELATED_GAP=AGENT-002
RISK=MEDIUM
TEST_COVERAGE=tests/test_premium_capability_plane.py

PATH=src/orkio_v2/services/python_tool.py
STATUS=MODIFIED
PURPOSE=Keep legacy Python tool stdout/stderr as untrusted tool data.
RELATED_GAP=AGENT-002
RISK=MEDIUM
TEST_COVERAGE=full regression + Python authority regression

PATH=src/orkio_v2/services/realtime_execution.py
STATUS=MODIFIED
PURPOSE=Apply Hyper profile/system separation to realtime execution without changing thread authorization.
RELATED_GAP=AGENT-001
RISK=MEDIUM
TEST_COVERAGE=tests/test_realtime_stream_execution.py + full regression

PATH=tests/test_artifact_runtime_context_r04p3.py
STATUS=MODIFIED
PURPOSE=Regression for artifact metadata role boundary.
RELATED_GAP=ART-001
RISK=LOW
TEST_COVERAGE=SELF

PATH=tests/test_billing_asaas.py
STATUS=MODIFIED
PURPOSE=Regression for CSRF/provider-auth boundary and webhook body limit.
RELATED_GAP=BILL-001/BILL-002
RISK=LOW
TEST_COVERAGE=SELF

PATH=tests/test_blob_storage.py
STATUS=MODIFIED
PURPOSE=Regression for provider-managed R2-compatible storage mode.
RELATED_GAP=ARTIFACT-R2-001
RISK=LOW
TEST_COVERAGE=SELF

PATH=tests/test_document_context.py
STATUS=MODIFIED
PURPOSE=Regression for document authority boundary plus remote-only BlobStorage legacy reads and missing-blob mapping.
RELATED_GAP=KNOW-001 / DOCUMENT-R2-001
RISK=LOW
TEST_COVERAGE=SELF

PATH=tests/test_hyper_cocreator.py
STATUS=MODIFIED
PURPOSE=Regression proving profile injection cannot enter system authority.
RELATED_GAP=AGENT-001
RISK=LOW
TEST_COVERAGE=SELF

PATH=tests/test_internal_consultation_governance.py
STATUS=MODIFIED
PURPOSE=Regression for internal specialist contribution authority.
RELATED_GAP=AGENT-003
RISK=LOW
TEST_COVERAGE=SELF

PATH=tests/test_knowledge_plane.py
STATUS=MODIFIED
PURPOSE=Regression for Knowledge layer roles and ownership boundary.
RELATED_GAP=KNOW-002
RISK=LOW
TEST_COVERAGE=SELF

PATH=tests/test_premium_capability_plane.py
STATUS=MODIFIED
PURPOSE=Regression for external-read and Python-output prompt authority.
RELATED_GAP=WEB-001/AGENT-002
RISK=LOW
TEST_COVERAGE=SELF

## Tests

FOCUSED=python -m pytest -q tests/test_document_context.py tests/test_blob_storage.py
FOCUSED_RESULT=12 passed, 0 failed
FULL_REGRESSION=python -m pytest -q
FULL_REGRESSION_RESULT=883 passed, 8 skipped, 0 failed
COMPILE=python -m compileall -q src/orkio_v2 tests
COMPILE_RESULT=PASS
POSTGRESQL_RUNTIME=NÃO_PROVADO (psycopg/PostgreSQL 16-specific skips remain)
CLOUDFLARE_R2_LIVE_DOCUMENT_CONTEXT_SMOKE=NÃO_PROVADO

## Governance

GITHUB_WRITE=NOT_EXECUTED
COMMIT=NOT_EXECUTED
PUSH=NOT_EXECUTED
PR=NOT_EXECUTED
MERGE=NOT_EXECUTED
EXTERNAL_MIGRATION=NOT_EXECUTED
RAILWAY_CHANGE=NOT_EXECUTED
DEPLOY=NOT_EXECUTED
PRODUCTION_CHANGE=NOT_EXECUTED
