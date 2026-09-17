from __future__ import annotations
import hashlib
from ..image_providers.base import ImageGenerationResult

class ImageValidationError(RuntimeError): pass

def validate_image_result(result:ImageGenerationResult,*,max_bytes:int)->tuple[str,str]:
    data=result.data
    if not data: raise ImageValidationError("ARTIFACT_IMAGE_EMPTY")
    if len(data)>max_bytes: raise ImageValidationError("ARTIFACT_IMAGE_TOO_LARGE")
    mime=(result.mime_type or "").lower()
    if mime=="image/png":
        if not data.startswith(b"\x89PNG\r\n\x1a\n"): raise ImageValidationError("ARTIFACT_IMAGE_MAGIC_MISMATCH")
        ext=".png"
    elif mime in {"image/jpeg","image/jpg"}:
        if not (data.startswith(b"\xff\xd8") and data.endswith(b"\xff\xd9")): raise ImageValidationError("ARTIFACT_IMAGE_MAGIC_MISMATCH")
        ext=".jpg"
    elif mime=="image/webp":
        if len(data)<12 or data[:4]!=b"RIFF" or data[8:12]!=b"WEBP": raise ImageValidationError("ARTIFACT_IMAGE_MAGIC_MISMATCH")
        ext=".webp"
    else: raise ImageValidationError("ARTIFACT_IMAGE_MIME_UNSUPPORTED")
    return ext,hashlib.sha256(data).hexdigest()
