from pathlib import Path


ROOT = Path(__file__).parents[1]
REALTIME_ROUTES = (ROOT / "src/orkio_v2/realtime_routes.py").read_text()
EXECUTION = (ROOT / "src/orkio_v2/services/realtime_execution.py").read_text()
ROUTES = (ROOT / "src/orkio_v2/routes.py").read_text()


def test_incremental_route_preserves_canonical_receipt_and_terminal_events():
    assert '@router.post("/threads/{thread_id}/realtime/turns/stream")' in REALTIME_ROUTES
    assert "reserve_receipt(" in REALTIME_ROUTES
    assert "complete_receipt(" in REALTIME_ROUTES
    assert '"type": "done"' in REALTIME_ROUTES
    assert "CLIENT_DISCONNECTED" in REALTIME_ROUTES
    assert "fail_receipt(" in REALTIME_ROUTES


def test_incremental_route_emits_text_and_audio_segment_events():
    assert '"type": "text_delta"' in EXECUTION
    assert '"type": "segment_ready"' in EXECUTION
    assert '"type": "audio_segment"' in REALTIME_ROUTES
    assert "data_base64" in REALTIME_ROUTES
    assert "SentenceSegmenter" in EXECUTION


def test_stream_route_keeps_limits_and_legacy_fallback_primitives():
    assert "_REALTIME_STREAM_MAX_SEGMENTS" in REALTIME_ROUTES
    assert "_enforce_realtime_segment_limits" in REALTIME_ROUTES
    assert '"/threads/{thread_id}/realtime/turns"' in REALTIME_ROUTES
    assert "synthesize_speech(" in REALTIME_ROUTES


def test_chat_and_realtime_pass_allowlisted_admin_authorization_to_github_context():
    assert "github_context_messages" in ROUTES
    assert ROUTES.count("is_admin=is_allowlisted_admin(p, settings)") >= 2
    assert "from .github_integration import github_context_messages" in EXECUTION
    assert "is_admin: bool = False" in EXECUTION
    assert "github_context_messages(" in EXECUTION
