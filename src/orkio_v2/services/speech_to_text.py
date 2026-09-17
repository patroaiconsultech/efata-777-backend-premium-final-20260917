from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import Lock
from typing import Any, Callable

from ..config import Settings


@dataclass(frozen=True)
class TranscriptResult:
    text: str
    language: str | None
    language_probability: float | None
    engine: str
    model: str


class SpeechToTextError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


_LOCALE_TO_LANGUAGE = {
    "pt-br": "pt",
    "pt": "pt",
    "en-us": "en",
    "en": "en",
    "es-419": "es",
    "es-latam": "es",
    "es-mx": "es",
    "es": "es",
    "auto": None,
    "": None,
}

_model_cache: dict[tuple[str, str, str, str, bool], Any] = {}
_model_lock = Lock()


@dataclass
class _SttCapacity:
    limit: int
    active: int = 0
    lock: Lock = field(default_factory=Lock)

    def try_acquire(self) -> bool:
        with self.lock:
            if self.active >= self.limit:
                return False
            self.active += 1
            return True

    def release(self) -> None:
        with self.lock:
            self.active = max(0, self.active - 1)


_capacity_registry: dict[int, _SttCapacity] = {}
_capacity_registry_lock = Lock()


def _capacity_for(limit: int) -> _SttCapacity:
    with _capacity_registry_lock:
        capacity = _capacity_registry.get(limit)
        if capacity is None:
            capacity = _SttCapacity(limit=limit)
            _capacity_registry[limit] = capacity
        return capacity


def normalize_locale(locale: str | None) -> str | None:
    normalized = (locale or "auto").strip().lower()
    if normalized not in _LOCALE_TO_LANGUAGE:
        raise SpeechToTextError("STT_LOCALE_NOT_ALLOWED")
    return _LOCALE_TO_LANGUAGE[normalized]


def _allowed_languages(settings: Settings) -> set[str]:
    return {
        item.strip().lower()
        for item in settings.stt_allowed_languages.split(",")
        if item.strip()
    }


def _get_model(settings: Settings):
    if settings.stt_provider != "faster_whisper":
        raise SpeechToTextError("STT_PROVIDER_UNAVAILABLE")
    key = (
        settings.stt_model,
        settings.stt_device,
        settings.stt_compute_type,
        settings.stt_model_cache_dir,
        settings.stt_local_files_only,
    )
    with _model_lock:
        cached = _model_cache.get(key)
        if cached is not None:
            return cached
        try:
            from faster_whisper import WhisperModel
        except ImportError as exc:
            raise SpeechToTextError("STT_DEPENDENCY_NOT_INSTALLED") from exc
        try:
            model = WhisperModel(
                settings.stt_model,
                device=settings.stt_device,
                compute_type=settings.stt_compute_type,
                download_root=settings.stt_model_cache_dir,
                local_files_only=settings.stt_local_files_only,
            )
        except Exception as exc:
            raise SpeechToTextError("STT_MODEL_UNAVAILABLE") from exc
        _model_cache[key] = model
        return model


def _transcribe_sync(
    settings: Settings,
    audio_path: Path,
    requested_language: str | None,
) -> TranscriptResult:
    if requested_language and requested_language not in _allowed_languages(settings):
        raise SpeechToTextError("STT_LOCALE_NOT_ALLOWED")

    model = _get_model(settings)
    try:
        segments, info = model.transcribe(
            str(audio_path),
            language=requested_language,
            vad_filter=True,
            condition_on_previous_text=False,
        )
        materialized = list(segments)
    except SpeechToTextError:
        raise
    except Exception as exc:
        raise SpeechToTextError("STT_TRANSCRIPTION_FAILED") from exc

    text = " ".join(
        str(getattr(segment, "text", "") or "").strip()
        for segment in materialized
        if str(getattr(segment, "text", "") or "").strip()
    ).strip()
    if not text:
        raise SpeechToTextError("STT_EMPTY_TRANSCRIPT")

    language = getattr(info, "language", None)
    probability = getattr(info, "language_probability", None)
    return TranscriptResult(
        text=text,
        language=str(language) if language else requested_language,
        language_probability=float(probability) if probability is not None else None,
        engine="faster_whisper",
        model=settings.stt_model,
    )


def _transcribe_bytes_sync(
    settings: Settings,
    audio_bytes: bytes,
    suffix: str,
    requested_language: str | None,
) -> TranscriptResult:
    """Own the temporary audio file for exactly as long as the CPU worker needs it."""
    temp_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="wb",
            suffix=suffix,
            prefix="orkio-stt-",
            delete=False,
        ) as temp:
            temp.write(audio_bytes)
            temp.flush()
            temp_path = Path(temp.name)
        return _transcribe_sync(settings, temp_path, requested_language)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


async def _run_stt_worker(
    settings: Settings,
    worker_fn: Callable[..., TranscriptResult],
    *worker_args: object,
) -> TranscriptResult:
    if settings.stt_timeout_seconds <= 0:
        raise SpeechToTextError("STT_TIMEOUT_NOT_CONFIGURED")
    if settings.stt_concurrency_limit <= 0:
        raise SpeechToTextError("STT_CONCURRENCY_LIMIT_NOT_CONFIGURED")

    capacity = _capacity_for(settings.stt_concurrency_limit)
    if not capacity.try_acquire():
        raise SpeechToTextError("STT_CONCURRENCY_LIMIT_REACHED")

    worker = asyncio.create_task(
        asyncio.to_thread(
            worker_fn,
            *worker_args,
        )
    )
    release_deferred = False

    def _release_capacity(_task: asyncio.Task[TranscriptResult]) -> None:
        capacity.release()

    try:
        return await asyncio.wait_for(
            asyncio.shield(worker),
            timeout=settings.stt_timeout_seconds,
        )
    except TimeoutError as exc:
        if worker.done():
            capacity.release()
        else:
            worker.add_done_callback(_release_capacity)
        release_deferred = True
        raise SpeechToTextError("STT_TIMEOUT") from exc
    except asyncio.CancelledError:
        if worker.done():
            capacity.release()
        else:
            worker.add_done_callback(_release_capacity)
        release_deferred = True
        raise
    finally:
        if not release_deferred:
            capacity.release()


async def transcribe_audio(
    settings: Settings,
    audio_path: Path,
    *,
    locale: str | None,
) -> TranscriptResult:
    """Transcribe a caller-owned path. The caller remains responsible for path lifetime."""
    if not settings.stt_enabled:
        raise SpeechToTextError("STT_DISABLED")
    requested_language = normalize_locale(locale)
    return await _run_stt_worker(
        settings,
        _transcribe_sync,
        settings,
        audio_path,
        requested_language,
    )


async def transcribe_audio_bytes(
    settings: Settings,
    audio_bytes: bytes,
    *,
    suffix: str,
    locale: str | None,
) -> TranscriptResult:
    """Transcribe request audio with worker-owned tempfile lifetime.

    The tempfile is created and removed inside the CPU worker. If the HTTP coroutine
    times out or is cancelled, the worker may continue, but its audio file remains
    valid until that worker exits and performs cleanup.
    """
    if not settings.stt_enabled:
        raise SpeechToTextError("STT_DISABLED")
    requested_language = normalize_locale(locale)
    return await _run_stt_worker(
        settings,
        _transcribe_bytes_sync,
        settings,
        audio_bytes,
        suffix,
        requested_language,
    )


def inspect_stt_readiness(settings: Settings) -> dict[str, object]:
    """Cheap readiness probe: dependency + local model cache, without model inference."""
    enabled = bool(settings.stt_enabled)
    provider = settings.stt_provider
    result: dict[str, object] = {
        "enabled": enabled,
        "provider": provider,
        "model": settings.stt_model,
        "dependency_present": False,
        "model_cached": False,
        "local_files_only": settings.stt_local_files_only,
        "ready": False,
    }
    if provider != "faster_whisper":
        result["reason"] = "STT_PROVIDER_UNAVAILABLE" if enabled else "STT_DISABLED"
        return result

    try:
        from faster_whisper.utils import download_model
    except ImportError:
        result["reason"] = "STT_DEPENDENCY_NOT_INSTALLED"
        return result

    result["dependency_present"] = True
    model_path = Path(settings.stt_model)
    if model_path.is_dir():
        cached_path = model_path
    else:
        try:
            cached_path = Path(
                download_model(
                    settings.stt_model,
                    local_files_only=True,
                    cache_dir=settings.stt_model_cache_dir,
                )
            )
        except Exception:
            result["reason"] = "STT_MODEL_NOT_PREWARMED"
            return result

    required = {"config.json", "model.bin", "tokenizer.json"}
    present = {item.name for item in cached_path.iterdir()} if cached_path.is_dir() else set()
    result["model_cached"] = required.issubset(present)
    result["ready"] = bool(enabled and result["model_cached"])
    if not enabled:
        result["reason"] = "STT_DISABLED"
    elif not result["model_cached"]:
        result["reason"] = "STT_MODEL_NOT_PREWARMED"
    else:
        result["reason"] = None
    return result


def prewarm_stt_model(settings: Settings) -> dict[str, object]:
    """Load the configured model once so deployment can fail before demo traffic."""
    model = _get_model(settings)
    return {
        "provider": "faster_whisper",
        "model": settings.stt_model,
        "device": settings.stt_device,
        "compute_type": settings.stt_compute_type,
        "cache_dir": settings.stt_model_cache_dir,
        "loaded": model is not None,
    }

