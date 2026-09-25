"""Authentication HTTP endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status

from src.schemas.auth import ForgotPasswordRequest, ForgotPasswordResponse
from src.services.auth import AuthService, get_auth_service


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    status_code=status.HTTP_200_OK,
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> ForgotPasswordResponse:
    """Issue the registered account's one-time password-reset token."""
    reset_token = auth_service.issue_password_reset_token(str(payload.email))
    if reset_token is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No registered account found for this email address",
        )
    return ForgotPasswordResponse(reset_token=reset_token)
