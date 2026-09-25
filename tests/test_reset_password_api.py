from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from src.main import app
from src.services.auth import AuthService, get_auth_service


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "not-an-email", "reset_token": "token", "new_password": "password1"},
        {
            "email": "person@example.com",
            "reset_token": "token",
            "new_password": "short",
        },
        {"email": "person@example.com", "new_password": "password1"},
    ],
)
def test_reset_password_rejects_invalid_request_payload(payload: dict[str, str]) -> None:
    response = TestClient(app).post("/api/v1/auth/reset-password", json=payload)

    assert response.status_code == 422


def test_reset_password_rejects_an_expired_token() -> None:
    service = AuthService(
        registered_emails=["person@example.com"],
        reset_token_ttl=timedelta(seconds=-1),
    )
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
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid or already used password reset token"
