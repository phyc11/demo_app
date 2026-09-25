from src.core.security import hash_password
from datetime import timedelta

from src.services.auth import AuthService


def test_reset_token_is_associated_with_the_registered_email() -> None:
    service = AuthService(registered_emails=["person@example.com"])

    token = service.issue_password_reset_token("PERSON@example.com")

    assert token is not None
    assert set(service.reset_tokens) == {"person@example.com"}
    stored_token = service.reset_tokens["person@example.com"]
    assert stored_token.email == "person@example.com"
    assert stored_token.used is False


def test_password_hash_is_persisted_in_the_auth_database(tmp_path) -> None:
    database_path = tmp_path / "auth.sqlite3"
    service = AuthService(
        registered_emails=["person@example.com"], database_path=str(database_path)
    )
    reset_token = service.issue_password_reset_token("person@example.com")
    assert reset_token is not None
    new_password_hash = hash_password("new-secure-password")

    assert service.reset_password(
        "person@example.com", reset_token, new_password_hash
    )

    reloaded_service = AuthService(database_path=str(database_path))
    assert reloaded_service.password_hashes["person@example.com"] == new_password_hash
    assert reloaded_service.reset_tokens["person@example.com"].used is True
    assert not reloaded_service.is_password_reset_token_valid(
        "person@example.com", reset_token
    )


def test_expired_reset_token_is_rejected() -> None:
    service = AuthService(
        registered_emails=["person@example.com"],
        reset_token_ttl=timedelta(seconds=-1),
    )
    reset_token = service.issue_password_reset_token("person@example.com")
    assert reset_token is not None

    assert not service.is_password_reset_token_valid("person@example.com", reset_token)
    assert not service.reset_password(
        "person@example.com", reset_token, hash_password("new-secure-password")
    )
