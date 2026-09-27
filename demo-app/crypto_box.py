"""Encryption at rest and credential derivation.

Two separate jobs that are often confused:

  EncryptedString    reversible Fernet (AES-128-CBC with an HMAC tag) over a
                     stored value, used where the platform has to read the value
                     back, for example to print a delivery address on a label.

  hash_password      one way PBKDF2-HMAC-SHA256 over a credential, used where the
                     platform must never be able to read the value back.

A lookup digest is kept beside the encrypted email because Fernet output is not
deterministic, so an encrypted column cannot be used in a WHERE clause. The
digest is a keyed HMAC, not a bare hash, so the column cannot be attacked with a
precomputed table of common addresses.
"""

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import String
from sqlalchemy.types import TypeDecorator

# A real deployment reads these from a KMS or from the process environment. A
# local fixture generates them once and keeps them next to the database file so
# the two stay in step across restarts.
KEY_FILE = Path(__file__).with_name("local_keys.txt")

PBKDF2_ITERATIONS = 240_000
SALT_BYTES = 16
CREDENTIAL_ALGORITHM = "pbkdf2_sha256"


def _load_local_keys() -> tuple[bytes, bytes]:
    if KEY_FILE.exists():
        lines = KEY_FILE.read_text(encoding="utf-8").split()
        if len(lines) == 2:
            return lines[0].encode("ascii"), lines[1].encode("ascii")
    at_rest = Fernet.generate_key()
    lookup = secrets.token_hex(32).encode("ascii")
    KEY_FILE.write_text(
        f"{at_rest.decode('ascii')}\n{lookup.decode('ascii')}\n", encoding="utf-8"
    )
    return at_rest, lookup


_AT_REST_KEY, _LOOKUP_KEY = _load_local_keys()
_CIPHER = Fernet(_AT_REST_KEY)


class EncryptedString(TypeDecorator):
    """A column whose plaintext never reaches the database file.

    Rules 2025 rule 6 asks for encryption, masking or tokenisation over personal
    data. This is the encryption option, applied per column rather than per disk,
    so a copied database file is useless without the key.
    """

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return _CIPHER.encrypt(str(value).encode("utf-8")).decode("ascii")

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            return _CIPHER.decrypt(value.encode("ascii")).decode("utf-8")
        except InvalidToken:
            return None


def lookup_digest(plain_value: str) -> str:
    """Keyed digest used to find a row without decrypting the whole table."""
    normalised = (plain_value or "").strip().lower().encode("utf-8")
    return hmac.new(_LOOKUP_KEY, normalised, digestmod="sha256").hexdigest()


def hash_password(raw_secret: str) -> str:
    """Derive a stored credential with a deliberately slow function."""
    salt = os.urandom(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        "sha256", (raw_secret or "").encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"{CREDENTIAL_ALGORITHM}${PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(raw_secret: str, stored: str) -> bool:
    """Constant time comparison against a stored PBKDF2 credential."""
    if not stored:
        return False
    parts = stored.split("$")
    if len(parts) != 4 or parts[0] != CREDENTIAL_ALGORITHM:
        return False
    rounds = int(parts[1])
    salt = bytes.fromhex(parts[2])
    derived = hashlib.pbkdf2_hmac(
        "sha256", (raw_secret or "").encode("utf-8"), salt, rounds
    )
    return hmac.compare_digest(derived.hex(), parts[3])


def session_signing_key() -> str:
    """Key the browser session cookie is signed with."""
    return hashlib.sha512(_LOOKUP_KEY).hexdigest()


def principal_reference(principal_id: int) -> str:
    """Stable per-account reference used by the local analytics counters.

    Not reversible without the lookup key, and never joined back to a name or an
    address in the analytics tables.
    """
    return hmac.new(
        _LOOKUP_KEY, str(principal_id).encode("ascii"), digestmod="sha256"
    ).hexdigest()[:32]
