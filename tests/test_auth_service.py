from src.services.auth import AuthService


def test_reset_token_is_associated_with_the_registered_email() -> None:
    service = AuthService(registered_emails=["person@example.com"])

    token = service.issue_password_reset_token("PERSON@example.com")

    assert token is not None
    assert set(service.reset_tokens) == {"person@example.com"}
    stored_token = service.reset_tokens["person@example.com"]
    assert stored_token.email == "person@example.com"
    assert stored_token.used is False
