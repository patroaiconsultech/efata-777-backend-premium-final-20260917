from fastapi.testclient import TestClient

from orkio_v2.main import app


FRONTEND_ORIGIN = "https://plataforma-efata-777-frontend-production.up.railway.app"


def test_public_applications_preflight_accepts_frontend_headers():
    response = TestClient(app).options(
        "/api/public/applications",
        headers={
            "Origin": FRONTEND_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type, x-orkio-csrf",
        },
    )

    assert response.status_code == 200, response.text
    assert response.headers["access-control-allow-origin"] == FRONTEND_ORIGIN
    assert "x-orkio-csrf" in response.headers["access-control-allow-headers"].lower()
    assert "/api/public/applications" in app.openapi()["paths"]
