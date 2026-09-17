from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_docker_installs_stt_extra_and_runs_import_smoke():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "pip install --no-cache-dir --require-hashes -r requirements.lock.txt" in dockerfile
    assert "import faster_whisper; import orkio_v2.main" in dockerfile
    assert "PYTHONPATH=/app/src" in dockerfile


def test_docker_has_optional_build_time_model_prewarm():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'ARG ORKIO_STT_PREWARM_MODEL=""' in dockerfile
    assert "python scripts/prewarm_stt.py" in dockerfile
    assert "PLATFORM_STT_MODEL_CACHE_DIR=" + "/opt/orkio/models/faster-whisper" in dockerfile


def test_prewarm_script_is_packaged_in_source_tree():
    script = (ROOT / "scripts" / "prewarm_stt.py").read_text(encoding="utf-8")
    assert "prewarm_stt_model" in script
    assert "STT_PROVIDER_UNAVAILABLE" in script


def test_stt_dependency_is_exactly_pinned_for_demo_image():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'stt = ["faster-whisper==1.2.1"]' in pyproject
    assert "faster-whisper>=1" not in pyproject


def test_smoke_plan_is_materialized():
    smoke = (ROOT / "SMOKE_PLAN_A2_1_1.md").read_text(encoding="utf-8")
    required = [
        "same thread",
        "same selected agent",
        "record Thread A",
        "switch Thread B",
        "STT_TIMEOUT",
        "STT_CONCURRENCY_LIMIT_REACHED",
        "mic released",
        "real PT-BR",
        "rollback",
    ]
    for marker in required:
        assert marker in smoke

def test_build_time_prewarm_does_not_enable_runtime_stt_contract():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    prewarm_block = dockerfile.split('ARG ORKIO_STT_PREWARM_MODEL=""', 1)[1]
    assert "python scripts/prewarm_stt.py" in prewarm_block
    assert "PLATFORM_STT_PROVIDER=faster_whisper" in prewarm_block
    assert "PLATFORM_STT_ENABLED=true" not in prewarm_block

