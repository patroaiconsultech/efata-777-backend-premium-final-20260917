from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from ..config import Settings
from .voice_binding import VoiceProfile


class TextToSpeechError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def message_content_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def synthesis_identity(
    *,
    tenant_id: str,
    thread_id: str,
    message_id: str,
    locale: str,
    profile: VoiceProfile,
    content_sha256: str,
) -> str:
    canonical = "\n".join(
        [
            tenant_id,
            thread_id,
            message_id,
            locale,
            profile.binding_id,
            profile.binding_version,
            content_sha256,
            profile.provider,
            profile.model,
            profile.voice_id,
            profile.provider_profile_version,
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def request_idempotency_identity(
    *,
    tenant_id: str,
    actor_id: str,
    idempotency_key: str,
    synthesis_identity_value: str,
) -> str:
    key = idempotency_key.strip()
    if not key or len(key) > 200:
        raise TextToSpeechError("TTS_IDEMPOTENCY_KEY_INVALID")
    canonical = "\n".join(
        [
            tenant_id,
            actor_id,
            key,
            synthesis_identity_value,
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _idempotency_root(settings: Settings) -> Path:
    root = Path(settings.tts_cache_path).resolve()
    target = (root / "_idempotency").resolve()
    if target != root and root not in target.parents:
        raise TextToSpeechError("TTS_CACHE_PATH_INVALID")
    return target


def idempotency_response_path(settings: Settings, identity: str) -> Path:
    root = _idempotency_root(settings)
    target = (root / identity[:2] / f"{identity}.mp3").resolve()
    if target != root and root not in target.parents:
        raise TextToSpeechError("TTS_CACHE_PATH_INVALID")
    return target


def read_idempotent_speech(settings: Settings, identity: str) -> bytes | None:
    path = idempotency_response_path(settings, identity)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    return raw or None


@dataclass(frozen=True)
class TTSIdempotencyReservation:
    identity: str
    response_path: Path
    lock_path: Path
    owner: bool
    replay_audio: bytes | None = None


async def reserve_tts_idempotency(
    settings: Settings,
    identity: str,
) -> TTSIdempotencyReservation:
    response_path = idempotency_response_path(settings, identity)
    response_path.parent.mkdir(parents=True, exist_ok=True)
    replay = read_idempotent_speech(settings, identity)
    lock_path = response_path.with_suffix(".lock")
    if replay is not None:
        return TTSIdempotencyReservation(
            identity=identity,
            response_path=response_path,
            lock_path=lock_path,
            owner=False,
            replay_audio=replay,
        )

    wait_seconds = max(float(settings.tts_http_timeout_seconds), 1.0)
    deadline = time.monotonic() + wait_seconds
    stale_after = max(wait_seconds * 2.0, 10.0)

    while True:
        try:
            fd = os.open(
                lock_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            replay = read_idempotent_speech(settings, identity)
            if replay is not None:
                return TTSIdempotencyReservation(
                    identity=identity,
                    response_path=response_path,
                    lock_path=lock_path,
                    owner=False,
                    replay_audio=replay,
                )
            try:
                age = time.time() - lock_path.stat().st_mtime
            except FileNotFoundError:
                continue
            if age > stale_after:
                try:
                    lock_path.unlink()
                except FileNotFoundError:
                    pass
                continue
            if time.monotonic() >= deadline:
                raise TextToSpeechError("TTS_IDEMPOTENCY_IN_PROGRESS")
            await asyncio.sleep(0.05)
            continue

        try:
            os.write(fd, f"pid={os.getpid()}\n".encode("ascii"))
        finally:
            os.close(fd)
        return TTSIdempotencyReservation(
            identity=identity,
            response_path=response_path,
            lock_path=lock_path,
            owner=True,
        )


def complete_tts_idempotency(
    reservation: TTSIdempotencyReservation,
    audio: bytes,
) -> None:
    if not reservation.owner:
        return
    if not audio:
        raise TextToSpeechError("TTS_PROVIDER_UNAVAILABLE")
    tmp = reservation.response_path.with_suffix(
        f".{os.getpid()}.tmp"
    )
    tmp.write_bytes(audio)
    tmp.replace(reservation.response_path)


def release_tts_idempotency(
    reservation: TTSIdempotencyReservation | None,
) -> None:
    if reservation is None or not reservation.owner:
        return
    try:
        reservation.lock_path.unlink()
    except FileNotFoundError:
        pass


def cache_path(settings: Settings, identity: str) -> Path:
    root = Path(settings.tts_cache_path).resolve()
    target = (root / identity[:2] / f"{identity}.mp3").resolve()
    if target != root and root not in target.parents:
        raise TextToSpeechError("TTS_CACHE_PATH_INVALID")
    return target


def read_cached_speech(settings: Settings, identity: str) -> bytes | None:
    if not settings.tts_cache_enabled:
        return None
    path = cache_path(settings, identity)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    return raw or None


def write_cached_speech(settings: Settings, identity: str, audio: bytes) -> None:
    if not settings.tts_cache_enabled:
        return
    path = cache_path(settings, identity)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(audio)
    tmp.replace(path)


async def synthesize_speech(
    settings: Settings,
    profile: VoiceProfile,
    text: str,
    *,
    request_id: str,
) -> bytes:
    del request_id  # correlation is logged by the route; never sent as a provider secret.
    if not settings.tts_enabled:
        raise TextToSpeechError("TTS_DISABLED")
    if profile.provider != "openai" or settings.tts_provider != "openai":
        raise TextToSpeechError("TTS_PROVIDER_UNAVAILABLE")
    if not (settings.openai_api_key or "").strip():
        raise TextToSpeechError("TTS_PROVIDER_UNAVAILABLE")
    if not text.strip():
        raise TextToSpeechError("TTS_EMPTY_CONTENT")
    if len(text) > settings.tts_max_chars:
        raise TextToSpeechError("TTS_COST_GUARD_REJECTED")

    base = (settings.openai_api_base or "https://api.openai.com/v1").rstrip("/")
    payload = {
        "model": profile.model,
        "voice": profile.voice_id,
        "input": text,
        "response_format": "mp3",
    }
    try:
        async with httpx.AsyncClient(timeout=settings.tts_http_timeout_seconds) as client:
            response = await client.post(
                f"{base}/audio/speech",
                headers={
                    "Authorization": f"Bearer {settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
                content=json.dumps(payload),
            )
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        raise TextToSpeechError("TTS_TIMEOUT") from exc
    except httpx.HTTPError as exc:
        raise TextToSpeechError("TTS_PROVIDER_UNAVAILABLE") from exc

    audio = bytes(response.content)
    if not audio:
        raise TextToSpeechError("TTS_PROVIDER_UNAVAILABLE")
    return audio
