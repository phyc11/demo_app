from fastapi.testclient import TestClient

from src.core.security import verify_password
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


def test_reset_password_verifies_token_hashes_password_and_revokes_token() -> None:
    service = AuthService(registered_emails=["person@example.com"])
    reset_token = service.issue_password_reset_token("person@example.com")
    assert reset_token is not None
    app.dependency_overrides[get_auth_service] = lambda: service

    try:
        response = TestClient(app).post(
            "/api/v1/auth/reset-password",
            json={
                "email": "person@example.com",
                "reset_token": reset_token,
                "new_password": "new-secure-password",
            },
        )
        repeat_response = TestClient(app).post(
            "/api/v1/auth/reset-password",
            json={
                "email": "person@example.com",
                "reset_token": reset_token,
                "new_password": "another-password",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert service.reset_tokens["person@example.com"].used is True
    assert service.password_hashes["person@example.com"] != "new-secure-password"
    assert verify_password(
        "new-secure-password", service.password_hashes["person@example.com"]
    )
    assert repeat_response.status_code == 400
    assert repeat_response.json()["detail"] == "Invalid or already used password reset token"


def test_reset_password_rejects_an_invalid_token() -> None:
    service = AuthService(registered_emails=["person@example.com"])
    app.dependency_overrides[get_auth_service] = lambda: service

    try:
        response = TestClient(app).post(
            "/api/v1/auth/reset-password",
            json={
                "email": "person@example.com",
                "reset_token": "invalid-token",
                "new_password": "new-secure-password",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid or already used password reset token"
