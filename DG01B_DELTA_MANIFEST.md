# DG01B_DELTA_MANIFEST

AGENT=DG-01B
WORKSTREAM=Identity/Auth / Mobile Session Boundary
PATCH=AUTH-MOBILE-001 + AUTH-CORS-001
BASE_REPOSITORY=https://github.com/patroaiconsultech/efata-777-backend-premium-final-20260917
BASE_BRANCH=NOT_PROVEN
BASE_HEAD_SHA=NOT_PROVEN
BASE_TREE_SHA=NOT_PROVEN
BASELINE_ARCHIVE_SHA256=0a894cf4b25a93e8ed656cb02ce34e67549eb72f1c4da508ed71d6339e4c13b4
PACKAGE_CREATED_AT=2026-10-05

ADDED:
- tests/test_csrf_cors_boundary.py

MODIFIED:
- src/orkio_v2/main.py

DELETED:
NONE

UNCHANGED_NOT_INCLUDED:
ALL_OTHER_BASELINE_PATHS

MIGRATIONS_INCLUDED:
NONE

TESTS_ADDED_OR_CHANGED:
- tests/test_csrf_cors_boundary.py

PURPOSE:
CORS middleware now wraps CSRF/security middleware so allowed-origin fail-closed
403 responses remain readable by the browser. No CSRF bypass or login exemption
is added.

TESTS:
- focused: 3 passed / 0 failed
- patched full baseline: 894 passed / 5 failed / 8 skipped
- unmodified supplied baseline: 892 passed / 5 failed / 8 skipped
- NEW_REGRESSION_FROM_THIS_PATCH=0
- FULL_SUITE_GREEN=NO
- compileall=PASS_LOCAL

PREEXISTING_BASELINE_FAILURES:
- tests/test_hp001_multiuser_self_knowledge.py::test_hp001_external_guest_from_join_send_revoke_and_reinvite
- tests/test_knowledge_plane.py::test_chat_and_team_history_share_governed_retrieval
- tests/test_r04b_canonical_direct_integration.py::test_handoff_history_reclassifies_previous_agent_as_context
- tests/test_realtime_execution_diagnostics.py::test_real_realtime_direct_executor_accepts_canonical_session_owner
- tests/test_realtime_stream_execution.py::test_stream_realtime_direct_emits_segments_before_terminal_commit

KNOWN_LIMITATIONS:
- mobile runtime after patch: NOT_PROVEN
- exact browser cookie-loss mechanism: NOT_PROVEN
- Railway source/config binding: NOT_PROVEN

CROSS_WORKSTREAM_DEPENDENCIES:
- frontend same-origin proxy delta

ROLLBACK:
- restore src/orkio_v2/main.py baseline SHA256 1fa1617e9e5f1d11cf745d9f50f103deeab4394b873e38f2fe3431cb5dfb4127
- delete tests/test_csrf_cors_boundary.py
- DB rollback: NONE

APPLY_ORDER:
1. AO-01 review
2. backend delta
3. frontend delta + config
4. controlled mobile smoke
