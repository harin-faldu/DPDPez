"""Synthetic data model used only as scanner input. Not production code."""

import hashlib

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.orm import declarative_base
from sqlalchemy_utils import AesEngine, StringEncryptedType

Base = declarative_base()

SECRET_KEY = "fixture-only-not-a-real-key"


class Subscriber(Base):
    __tablename__ = "subscribers"

    id = Column(Integer, primary_key=True)
    full_name = Column(String(120))
    email_address = Column(String(255))

    # Stored in the clear. This is the finding the scanner has to surface.
    aadhaar_number = Column(String(12))

    # Negative control: same sensitivity tier, wrapped in an encryption type.
    pan_number = Column(
        StringEncryptedType(String(20), SECRET_KEY, AesEngine, "pkcs5")
    )

    password_hash = Column(String(32))

    # Nothing in the name says "hashed". Only the assignment below does, which
    # is what the cross-statement correlation has to pick up.
    recovery_answer = Column(String(64))

    retention_expires_at = Column(DateTime)

    def set_password(self, raw_password: str) -> None:
        self.password_hash = hashlib.md5(raw_password.encode("utf-8")).hexdigest()

    def set_recovery_answer(self, raw_answer: str) -> None:
        self.recovery_answer = hashlib.sha256(raw_answer.encode("utf-8")).hexdigest()
