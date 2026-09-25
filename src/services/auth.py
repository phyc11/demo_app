"""In-memory authentication service primitives.

The reset-token record deliberately contains only a SHA-256 digest, never the
bearer token itself.  The plaintext value is returned only when it is issued.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from hmac import compare_digest
from secrets import token_urlsafe
from sqlite3 import Connection, connect
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

    def __init__(
        self,
        registered_emails: Iterable[str] | None = None,
        database_path: str = ":memory:",
    ) -> None:
        self.registered_emails = {
            self._normalise_email(email) for email in (registered_emails or ())
        }
        self._lock = Lock()
        self._database: Connection = connect(database_path, check_same_thread=False)
        self._database.execute(
            """
            CREATE TABLE IF NOT EXISTS password_credentials (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
            """
        )
        self._database.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                email TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        self._database.commit()

    @property
    def password_hashes(self) -> dict[str, str]:
        """Expose stored password hashes for service consumers and tests.

        Passwords themselves are never persisted: the database table contains
        only values returned from ``hash_password``.
        """
        with self._lock:
            rows = self._database.execute(
                "SELECT email, password_hash FROM password_credentials"
            ).fetchall()
        return {email: password_hash for email, password_hash in rows}

    @property
    def reset_tokens(self) -> dict[str, PasswordResetToken]:
        """Return reset-token records stored in the authentication database."""
        with self._lock:
            rows = self._database.execute(
                "SELECT email, token_hash, revoked, created_at FROM password_reset_tokens"
            ).fetchall()
        return {
            email: PasswordResetToken(
                email=email,
                token_hash=token_hash,
                used=bool(revoked),
                created_at=datetime.fromisoformat(created_at),
            )
            for email, token_hash, revoked, created_at in rows
        }

    def _get_reset_token(self, email: str) -> PasswordResetToken | None:
        row = self._database.execute(
            """
            SELECT email, token_hash, revoked, created_at
            FROM password_reset_tokens
            WHERE email = ?
            """,
            (email,),
        ).fetchone()
        if row is None:
            return None
        stored_email, token_hash, revoked, created_at = row
        return PasswordResetToken(
            email=stored_email,
            token_hash=token_hash,
            used=bool(revoked),
            created_at=datetime.fromisoformat(created_at),
        )

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
            self._database.execute(
                """
                INSERT INTO password_reset_tokens (email, token_hash, revoked, created_at)
                VALUES (?, ?, 0, ?)
                ON CONFLICT(email) DO UPDATE SET
                    token_hash = excluded.token_hash,
                    revoked = 0,
                    created_at = excluded.created_at
                """,
                (
                    normalised_email,
                    sha256(token.encode("utf-8")).hexdigest(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._database.commit()
            return token

    def consume_password_reset_token(self, email: str, token: str) -> bool:
        """Validate and atomically mark a reset token as used."""
        normalised_email = self._normalise_email(email)
        token_hash = sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            record = self._get_reset_token(normalised_email)
            if record is None or record.used:
                return False
            if not compare_digest(record.token_hash, token_hash):
                return False
            self._database.execute(
                "UPDATE password_reset_tokens SET revoked = 1 WHERE email = ?",
                (normalised_email,),
            )
            self._database.commit()
            return True

    def is_password_reset_token_valid(self, email: str, token: str) -> bool:
        """Return whether ``token`` is the current unused token for ``email``."""
        normalised_email = self._normalise_email(email)
        token_hash = sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            record = self._get_reset_token(normalised_email)
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
            record = self._get_reset_token(normalised_email)
            if record is None or record.used:
                return False
            if not compare_digest(record.token_hash, token_hash):
                return False
            self._database.execute(
                """
                INSERT INTO password_credentials (email, password_hash)
                VALUES (?, ?)
                ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash
                """,
                (normalised_email, password_hash),
            )
            self._database.execute(
                "UPDATE password_reset_tokens SET revoked = 1 WHERE email = ?",
                (normalised_email,),
            )
            self._database.commit()
            return True


auth_service = AuthService()


def get_auth_service() -> AuthService:
    """FastAPI dependency for the shared authentication service."""
    return auth_service
