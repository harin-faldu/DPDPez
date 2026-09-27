"""Database models and data access for the demo storefront.

WARNING: intentionally vulnerable demo fixture. Do not run on a public host.
See README.md for the full violation table.

Every value the app ever holds is synthetic. There are no real Aadhaar, PAN,
card or contact details anywhere in this tree, including in the seed data.
"""

from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

from crypto_utils import encrypt_value

db = SQLAlchemy()


class User(db.Model):
    """A storefront customer.

    VIOLATION (Retention, s.8(7)): no expires_at, retention_until or ttl column
    on this table or any other. Once a row is written it is kept forever and
    nothing in the codebase ever deletes it.
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(160), nullable=False)
    phone_number = db.Column(db.String(20))
    address_line = db.Column(db.String(240))

    # VIOLATION (R5, s.9): date of birth is collected at signup and stored,
    # but no code path anywhere computes an age from it, gates the account, or
    # asks for verifiable parental consent.
    date_of_birth = db.Column(db.String(10))

    # VIOLATION (R6, s.8(5)): Aadhaar is a critical identifier held in the
    # clear. No column level encryption, no tokenisation, no masking.
    aadhaar_number = db.Column(db.String(12))

    # VIOLATION (R6, s.8(5)): account password stored as a bare md5 digest.
    password_md5 = db.Column(db.String(32))

    # NEGATIVE CONTROL: PAN is encrypted at rest with Fernet before the write.
    # This is the one identifier column that is handled correctly.
    pan_number_encrypted = db.Column(db.LargeBinary)

    # NEGATIVE CONTROL: support PIN kept as a salted PBKDF2 digest.
    support_pin_pbkdf2 = db.Column(db.String(200))

    # VIOLATION (R4, s.6): one blanket boolean covering every purpose at once.
    # There is no per purpose record, no timestamp, no notice version, and
    # nothing in the codebase ever reads this column back before processing.
    consent_all = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def create_user(
    *,
    full_name: str,
    email: str,
    phone_number: str,
    address_line: str,
    date_of_birth: str,
    password_md5: str,
    support_pin_pbkdf2: str,
    consent_all: bool,
) -> User:
    """Insert a new signup row.

    VIOLATION (R4, s.6): consent_all is persisted as data but never used as a
    condition. The row is written whether the box was ticked or not.
    """
    user = User(
        full_name=full_name,
        email=email,
        phone_number=phone_number,
        address_line=address_line,
        date_of_birth=date_of_birth,
        password_md5=password_md5,
        support_pin_pbkdf2=support_pin_pbkdf2,
        consent_all=consent_all,
    )
    db.session.add(user)
    db.session.commit()
    return user


def store_kyc_record(user_id: int, aadhaar_number: str, pan_number: str) -> User | None:
    """Write the KYC identifiers onto an existing user row.

    This is the db_write sink of the cross file Aadhaar flow that starts at
    POST /kyc. Aadhaar lands in the clear, PAN is encrypted first.
    """
    user = db.session.get(User, user_id)
    if user is None:
        return None

    # VIOLATION (R6, s.8(5)): plaintext write of a critical identifier.
    user.aadhaar_number = aadhaar_number

    # NEGATIVE CONTROL: same route, same request, handled properly.
    user.pan_number_encrypted = encrypt_value(pan_number)

    db.session.commit()
    return user


def load_user_record(user_id: int) -> User | None:
    """Read a user row back out.

    VIOLATION (R12, s.8(1)): every read of personal data goes through here and
    nothing is recorded about who read what or why. There is no audit trail the
    company could produce to demonstrate compliance.
    """
    return db.session.get(User, user_id)
