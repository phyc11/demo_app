"""Schemas used by authentication endpoints."""

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    """Payload used when registering an account."""

    email: EmailStr
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    """Payload used when signing in."""

    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    """Payload used to request a password-reset token.

    This intentionally mirrors the email field used by ``RegisterRequest`` and
    ``LoginRequest``.  ``EmailStr`` makes Pydantic reject malformed payloads
    before the endpoint calls ``AuthService``.
    """

    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    """Token returned to the caller so it can be delivered to the user."""

    reset_token: str
    message: str = "Password reset token issued"


class ResetPasswordRequest(BaseModel):
    """Payload used to consume a password-reset token."""

    email: EmailStr
    reset_token: str = Field(min_length=1)
    new_password: str = Field(min_length=8)


class ResetPasswordResponse(BaseModel):
    """Confirmation returned after a password has been reset."""

    message: str = "Password reset successfully"
    token_revoked: bool = True
