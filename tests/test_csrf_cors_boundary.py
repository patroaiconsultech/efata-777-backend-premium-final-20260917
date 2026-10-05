from fastapi.testclient import TestClient

import orkio_v2.main as main_module


def test_csrf_403_keeps_cors_headers_for_allowed_origin(monkeypatch):
    origin = main_module._allowed_origins[0]
    monkeypatch.setattr(main_module.settings, "environment", "production")

    response = TestClient(main_module.app).post(
        "/api/v2/auth/login",
        headers={"Origin": origin},
        json={"email": "mobile@example.com", "password": "not-reached"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF_TOKEN_INVALID"}
    assert response.headers["access-control-allow-origin"] == origin
    assert response.headers["access-control-allow-credentials"] == "true"


def test_csrf_403_rejects_unallowed_origin_without_cors_grant(monkeypatch):
    monkeypatch.setattr(main_module.settings, "environment", "production")

    response = TestClient(main_module.app).post(
        "/api/v2/auth/login",
        headers={
            "Origin": "https://attacker.example",
            "X-ORKIO-CSRF": "synthetic",
        },
        json={"email": "mobile@example.com", "password": "not-reached"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF_ORIGIN_INVALID"}
    assert "access-control-allow-origin" not in response.headers
