"""Password hashing.

Clean build: PBKDF2-HMAC-SHA256 with a per-user random salt and a constant-time
comparison. The weak-crypto defect (S4) replaces both functions with a bare,
unsalted MD5 -- trivially reversible by a rainbow table, and flagged statically
by bandit (B324 / B303) the moment ``hashlib.md5(`` appears in the source.

Note what the *functional* tests cannot see: login works identically whether the
stored hash is PBKDF2 or MD5. Only a tool that reads the code (SAST) tells the
difference, which is exactly why a green login test is not evidence of safe
credential storage.
"""
import hashlib
import hmac
import os

from app.config import PBKDF2_ITERATIONS


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Return ``"<salt_hex>$<digest_hex>"`` for storage."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of ``password`` against a stored ``hash_password`` value."""
    salt_hex, _, digest_hex = stored.partition("$")
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    check = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(check.hex(), digest_hex)
