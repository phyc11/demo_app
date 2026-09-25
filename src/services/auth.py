"""In-memory authentication service primitives.

The reset-token record deliberately contains only a SHA-256 digest, never the
bearer token itself.  The plaintext value is returned only when it is issued.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from hmac import compare_digest
from secrets import token_urlsafe
from threading import Lock
from typing import Iterable


@dataclass
class PasswordResetToken:
    email: str
    token_hash: str
    used: bool = False
    created_at: datetime | None = None


class AuthService:
    """Owns registered-email and password-reset-token state.

    In a production deployment these collections should be backed by the user
    and token repositories.  Keeping the token record here makes the ownership
    and single-use behaviour explicit for the current service layer.
    """

    def __init__(self, registered_emails: Iterable[str] | None = None) -> None:
        self.registered_emails = {
            self._normalise_email(email) for email in (registered_emails or ())
        }
        self.reset_tokens: dict[str, PasswordResetToken] = {}
        self.password_hashes: dict[str, str] = {}
        self._lock = Lock()

    @staticmethod
    def _normalise_email(email: str) -> str:
        return email.strip().lower()

    def register_email(self, email: str) -> None:
        """Register an email address (normally performed by ``register``)."""
        with self._lock:
            self.registered_emails.add(self._normalise_email(email))

    def issue_password_reset_token(self, email: str) -> str | None:
        """Issue a new token for a registered email.

        A new request replaces any earlier token for the same email, so at most
        one outstanding token can be consumed.  ``None`` means the email is not
        registered.
        """
        normalised_email = self._normalise_email(email)
        with self._lock:
            if normalised_email not in self.registered_emails:
                return None

            token = token_urlsafe(32)
            self.reset_tokens[normalised_email] = PasswordResetToken(
                email=normalised_email,
                token_hash=sha256(token.encode("utf-8")).hexdigest(),
                used=False,
                created_at=datetime.now(timezone.utc),
            )
            return token

    def consume_password_reset_token(self, email: str, token: str) -> bool:
        """Validate and atomically mark a reset token as used."""
        normalised_email = self._normalise_email(email)
        token_hash = sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            record = self.reset_tokens.get(normalised_email)
            if record is None or record.used:
                return False
            if not compare_digest(record.token_hash, token_hash):
                return False
            record.used = True
            return True

    def is_password_reset_token_valid(self, email: str, token: str) -> bool:
        """Return whether ``token`` is the current unused token for ``email``."""
        normalised_email = self._normalise_email(email)
        token_hash = sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            record = self.reset_tokens.get(normalised_email)
            return bool(
                record
                and not record.used
                and compare_digest(record.token_hash, token_hash)
            )

    def reset_password(self, email: str, token: str, password_hash: str) -> bool:
        """Verify a token, store a new password hash, and revoke the token.

        The check and revocation occur under one lock so a token cannot reset
        more than one password when requests arrive concurrently.
        """
        normalised_email = self._normalise_email(email)
        token_hash = sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            record = self.reset_tokens.get(normalised_email)
            if record is None or record.used:
                return False
            if not compare_digest(record.token_hash, token_hash):
                return False
            self.password_hashes[normalised_email] = password_hash
            record.used = True
            return True


auth_service = AuthService()


def get_auth_service() -> AuthService:
    """FastAPI dependency for the shared authentication service."""
    return auth_service
