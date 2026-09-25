"""Password hashing helpers."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import scrypt
from hmac import compare_digest
from secrets import token_bytes


_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """Return a salted, memory-hard representation of ``password``."""
    salt = token_bytes(_SALT_BYTES)
    digest = scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
    )
    return "scrypt${}${}${}${}".format(
        _SCRYPT_N,
        _SCRYPT_R,
        _SCRYPT_P,
        f"{urlsafe_b64encode(salt).decode()}${urlsafe_b64encode(digest).decode()}",
    )


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password produced by :func:`hash_password`."""
    try:
        algorithm, n, r, p, salt, expected_digest = password_hash.split("$")
        if algorithm != "scrypt":
            return False
        actual_digest = scrypt(
            password.encode("utf-8"),
            salt=urlsafe_b64decode(salt.encode()),
            n=int(n),
            r=int(r),
            p=int(p),
        )
        return compare_digest(urlsafe_b64encode(actual_digest).decode(), expected_digest)
    except (TypeError, ValueError):
        return False
