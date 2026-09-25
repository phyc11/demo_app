"""Authentication HTTP endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status

from src.core.security import hash_password
from src.schemas.auth import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
)
from src.services.auth import AuthService, get_auth_service


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    status_code=status.HTTP_200_OK,
)
async def forgot_password(
    request: ForgotPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> ForgotPasswordResponse:
    """Issue the registered account's one-time password-reset token."""
    reset_token = auth_service.issue_password_reset_token(str(request.email))
    if reset_token is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No registered account found for this email address",
        )
    return ForgotPasswordResponse(reset_token=reset_token)


@router.post(
    "/reset-password",
    response_model=ResetPasswordResponse,
    status_code=status.HTTP_200_OK,
)
async def reset_password(
    request: ResetPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> ResetPasswordResponse:
    """Consume a valid reset token and replace the account password."""
    if not auth_service.is_password_reset_token_valid(
        str(request.email), request.reset_token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or already used password reset token",
        )
    new_password_hash = hash_password(request.new_password)
    reset_completed = auth_service.reset_password(
        str(request.email), request.reset_token, new_password_hash
    )
    if not reset_completed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or already used password reset token",
        )
    return ResetPasswordResponse()
