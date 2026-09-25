import pytest
from pydantic import ValidationError

from src.schemas.auth import ForgotPasswordRequest


def test_forgot_password_request_accepts_a_valid_email() -> None:
    request = ForgotPasswordRequest(email="person@example.com")

    assert str(request.email) == "person@example.com"


def test_forgot_password_request_rejects_an_invalid_email() -> None:
    with pytest.raises(ValidationError):
        ForgotPasswordRequest(email="not-an-email")
