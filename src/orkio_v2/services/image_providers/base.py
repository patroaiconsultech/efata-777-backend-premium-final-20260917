from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True, slots=True)
class ImageGenerationRequest:
    prompt: str
    width: int
    height: int
    request_id: str

@dataclass(frozen=True, slots=True)
class ImageGenerationResult:
    data: bytes
    mime_type: str
    provider: str
    model: str
    width: int
    height: int
    estimated_cost_usd: float | None = None

class ImageProvider(Protocol):
    def generate(self, request: ImageGenerationRequest) -> ImageGenerationResult: ...
