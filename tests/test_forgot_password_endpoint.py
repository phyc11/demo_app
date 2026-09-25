from fastapi.testclient import TestClient

from src.main import app
from src.services.auth import AuthService, get_auth_service


def test_forgot_password_issues_a_single_use_token_for_registered_email() -> None:
    service = AuthService(registered_emails=["person@example.com"])
    app.dependency_overrides[get_auth_service] = lambda: service

    try:
        response = TestClient(app).post(
            "/api/v1/auth/forgot-password",
            json={"email": "person@example.com"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    token = response.json()["reset_token"]
    assert token
    assert service.reset_tokens["person@example.com"].used is False
    assert service.consume_password_reset_token("person@example.com", token) is True
    assert service.consume_password_reset_token("person@example.com", token) is False


def test_forgot_password_rejects_an_invalid_email_payload() -> None:
    response = TestClient(app).post(
        "/api/v1/auth/forgot-password", json={"email": "not-an-email"}
    )

    assert response.status_code == 422
