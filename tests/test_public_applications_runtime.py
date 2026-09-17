from __future__ import annotations

import io

from fastapi.testclient import TestClient
from starlette.datastructures import Headers

from orkio_v2.main import app
from orkio_v2 import public_applications


FRONTEND_ORIGIN = "https://plataforma-efata-777-frontend-production.up.railway.app"


def _payload(**overrides):
    data = {
        "application_type": "career",
        "full_name": "Pessoa Teste",
        "email": "pessoa@example.com",
        "phone": "+5551999999999",
        "location": "Porto Alegre / RS",
        "interest_area": "Engenharia & IA",
        "introduction": "Experiência profissional relevante para a oportunidade.",
        "consent": "true",
        "website": "",
    }
    data.update(overrides)
    return data


def test_public_application_cors_preflight_allows_production_frontend():
    client = TestClient(app)
    response = client.options(
        "/api/public/applications",
        headers={
            "Origin": FRONTEND_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == FRONTEND_ORIGIN
    assert "POST" in response.headers["access-control-allow-methods"]


def test_public_application_route_is_registered_and_accepts_valid_pdf(monkeypatch):
    public_applications._rate_buckets.clear()
    captured = {}

    def fake_delivery(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(public_applications, "_deliver_application", fake_delivery)

    client = TestClient(app)
    response = client.post(
        "/api/public/applications",
        data=_payload(),
        files={
            "resume": (
                "curriculo.pdf",
                b"%PDF-1.7 test",
                "application/pdf",
            )
        },
        headers={"Origin": FRONTEND_ORIGIN},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["application_id"]
    assert captured["phone"] == "+5551999999999"
    assert response.headers["access-control-allow-origin"] == FRONTEND_ORIGIN


def test_public_application_consultant_requires_specialty(monkeypatch):
    public_applications._rate_buckets.clear()
    monkeypatch.setattr(public_applications, "_deliver_application", lambda **_: None)

    client = TestClient(app)
    response = client.post(
        "/api/public/applications",
        data=_payload(application_type="consultant"),
        files={
            "resume": (
                "curriculo.pdf",
                b"%PDF-1.7 test",
                "application/pdf",
            )
        },
        headers={"Origin": FRONTEND_ORIGIN},
    )

    assert response.status_code == 422
    assert (
        response.json()["detail"]["code"]
        == "PUBLIC_APPLICATION_CONSULTING_SPECIALTY_REQUIRED"
    )
