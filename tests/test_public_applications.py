from __future__ import annotations

import asyncio
import io

from fastapi import HTTPException, Request, UploadFile
from starlette.datastructures import Headers

from orkio_platform.api.routes import applications


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/public/applications",
            "headers": [],
            "client": ("127.0.0.1", 9999),
            "server": ("testserver", 80),
            "scheme": "http",
            "query_string": b"",
        }
    )


def _resume(
    name: str = "curriculo.pdf",
    content: bytes = b"%PDF-1.7 test",
) -> UploadFile:
    return UploadFile(
        file=io.BytesIO(content),
        filename=name,
        headers=Headers({"content-type": "application/pdf"}),
    )


def _submit_kwargs() -> dict:
    return {
        "request": _request(),
        "application_type": "career",
        "full_name": "Pessoa Teste",
        "email": "pessoa@example.com",
        "phone": "+55 51 99999-9999",
        "location": "Porto Alegre / RS",
        "interest_area": "Engenharia & IA",
        "introduction": "Experiência profissional relevante.",
        "consent": "true",
        "resume": _resume(),
        "linkedin_url": "",
        "portfolio_url": "",
        "experience_years": "",
        "availability": "",
        "consulting_specialty": "",
        "consulting_experience": "",
        "website": "",
    }


def test_helpers_validate_resume_and_filename():
    assert applications._safe_filename("../../cv pessoa.pdf") == "cv_pessoa.pdf"
    applications._validate_resume(
        "cv.pdf",
        "application/pdf",
        b"%PDF-1.7 test",
    )
    try:
        applications._validate_resume(
            "cv.pdf",
            "application/pdf",
            b"fake",
        )
    except HTTPException as exc:
        assert exc.status_code == 415
        assert exc.detail["code"] == "PUBLIC_APPLICATION_RESUME_SIGNATURE_INVALID"
    else:
        raise AssertionError("fake PDF should be rejected")


def test_submit_application_calls_delivery(monkeypatch):
    applications._rate_buckets.clear()
    captured = {}
    monkeypatch.setattr(
        applications,
        "_deliver_application",
        lambda **kwargs: captured.update(kwargs),
    )

    result = asyncio.run(
        applications.submit_public_application(**_submit_kwargs())
    )

    assert result["ok"] is True
    assert result["application_id"]
    assert captured["email"] == "pessoa@example.com"
    assert captured["filename"] == "curriculo.pdf"


def test_consultant_requires_specialty():
    applications._rate_buckets.clear()
    kwargs = _submit_kwargs()
    kwargs["application_type"] = "consultant"
    try:
        asyncio.run(
            applications.submit_public_application(**kwargs)
        )
    except HTTPException as exc:
        assert exc.status_code == 422
        assert exc.detail["code"] == "PUBLIC_APPLICATION_CONSULTING_SPECIALTY_REQUIRED"
    else:
        raise AssertionError("consultant specialty should be required")
