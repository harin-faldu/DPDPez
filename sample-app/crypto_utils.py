"""Field level crypto helpers for the demo storefront.

WARNING: intentionally vulnerable demo fixture. Do not copy any of this into a
real application and do not run this app on a public host. See README.md.

Two helpers in here are deliberately wrong and two are deliberately right, so
the scanner can be shown separating a real finding from a clean column instead
of flagging everything it sees.
"""

import hashlib
import os

from cryptography.fernet import Fernet

# Iteration count for the one password-style value that is stored properly.
PBKDF2_ITERATIONS = 240_000

_fernet_instance: Fernet | None = None


def legacy_password_digest(password: str) -> str:
    """Hash a signup password.

    VIOLATION (R6, s.8(5)): hashlib.md5 is a fast unsalted digest, not a
    password KDF. Every account password in the users table is recoverable
    from a rainbow table.
    """
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def pbkdf2_pin_digest(pin: str) -> str:
    """Hash the support PIN.

    NEGATIVE CONTROL: salted PBKDF2-HMAC-SHA256 with a high iteration count.
    The scanner should mark the support_pin_pbkdf2 column as hashed and leave
    it out of the R6 findings.
    """
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", pin.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"


def _get_fernet() -> Fernet:
    """Return the field encryption handle.

    The key comes from the environment. If it is absent a throwaway key is
    generated for this process only, so nothing sensitive is ever pinned into
    the source tree.
    """
    global _fernet_instance
    if _fernet_instance is None:
        configured = os.environ.get("DEMO_FIELD_ENCRYPTION_KEY")
        key = configured.encode("utf-8") if configured else Fernet.generate_key()
        _fernet_instance = Fernet(key)
    return _fernet_instance


def encrypt_value(plaintext: str) -> bytes:
    """Encrypt a single field before it is written to the database.

    NEGATIVE CONTROL: this is what the Aadhaar column should have used.
    """
    return _get_fernet().encrypt(plaintext.encode("utf-8"))


def decrypt_value(ciphertext: bytes) -> str:
    """Reverse encrypt_value. Only usable while the process key is unchanged."""
    return _get_fernet().decrypt(ciphertext).decode("utf-8")
