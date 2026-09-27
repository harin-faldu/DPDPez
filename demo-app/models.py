"""Storage schema for Bharat Bazaar.

Three conventions hold across every table that stores personal data:

  1. Anything that identifies a person is either an EncryptedString column or a
     keyed digest. There is no plaintext personal data in the database file.
  2. Every such table carries retain_until, so a row has an end date the moment
     it is written rather than an end date decided later by a human.
  3. Every such table declares the purposes it may be processed under through
     consent_purposes_for, which is the same register the notice page renders.

Known exceptions to rule 2 are listed in KNOWN_GAPS.md rather than hidden here.
"""

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

from crypto_box import EncryptedString
from purposes import consent_purposes_for

Base = declarative_base()

DATABASE_FILE = "bharat_bazaar.sqlite3"


def now_utc() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class DataPrincipal(Base):
    """A registered customer. Section 2(j) Data Principal."""

    __tablename__ = "data_principals"
    __consent_purposes__ = consent_purposes_for("account_management")

    id = Column(Integer, primary_key=True)
    email = Column(EncryptedString(512), nullable=False)
    email_digest = Column(String(64), nullable=False, unique=True, index=True)
    full_name = Column(EncryptedString(512), nullable=False)
    phone = Column(EncryptedString(256))
    dob = Column(EncryptedString(128))
    password_hash = Column(String(255), nullable=False)
    is_minor = Column(Boolean, nullable=False, default=False)
    marketing_suppressed = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=now_utc)
    retain_until = Column(DateTime, nullable=False)
    deleted_at = Column(DateTime)


class KycVerification(Base):
    """Identity documents held for the seller payout obligation."""

    __tablename__ = "kyc_verifications"
    __consent_purposes__ = consent_purposes_for("kyc_verification")

    id = Column(Integer, primary_key=True)
    principal_id = Column(Integer, ForeignKey("data_principals.id"), nullable=False)
    pan_number = Column(EncryptedString(256))
    aadhaar_last_four = Column(EncryptedString(128))
    address_line = Column(EncryptedString(1024))
    pincode = Column(EncryptedString(128))
    verification_status = Column(String(32), nullable=False, default="pending")
    verified_at = Column(DateTime)
    retain_until = Column(DateTime, nullable=False)


class ConsentRecord(Base):
    """One recorded act of consent or withdrawal.

    Section 6 needs the fiduciary to be able to show that consent was given, for
    what, when and against which version of the notice, so all four are columns
    rather than one boolean.
    """

    __tablename__ = "consent_records"
    __consent_purposes__ = consent_purposes_for("compliance_record")

    id = Column(Integer, primary_key=True)
    principal_id = Column(Integer, ForeignKey("data_principals.id"), nullable=False)
    purpose = Column(String(64), nullable=False)
    granted = Column(Boolean, nullable=False, default=False)
    consented_at = Column(DateTime, nullable=False, default=now_utc)
    withdrawn_at = Column(DateTime)
    policy_version = Column(String(32), nullable=False)
    channel = Column(String(32), nullable=False, default="web")
    retain_until = Column(DateTime, nullable=False)


class GuardianVerification(Base):
    """Verifiable consent of a parent or lawful guardian, section 9(1)."""

    __tablename__ = "guardian_verifications"
    __consent_purposes__ = consent_purposes_for("compliance_record")

    id = Column(Integer, primary_key=True)
    principal_id = Column(Integer, ForeignKey("data_principals.id"), nullable=False)
    guardian_email = Column(EncryptedString(512), nullable=False)
    guardian_name = Column(EncryptedString(512), nullable=False)
    verification_method = Column(String(64), nullable=False, default="email_challenge")
    challenge_digest = Column(String(64), nullable=False)
    verified_at = Column(DateTime)
    retain_until = Column(DateTime, nullable=False)


class Nomination(Base):
    """A person nominated under section 14 to exercise rights on an account."""

    __tablename__ = "nominations"
    __consent_purposes__ = consent_purposes_for("compliance_record")

    id = Column(Integer, primary_key=True)
    principal_id = Column(Integer, ForeignKey("data_principals.id"), nullable=False)
    nominee_name = Column(EncryptedString(512), nullable=False)
    nominee_email = Column(EncryptedString(512))
    relationship = Column(String(64))
    recorded_at = Column(DateTime, nullable=False, default=now_utc)
    retain_until = Column(DateTime, nullable=False)


class GrievanceTicket(Base):
    """Grievance intake under section 13, with the response clock on the row."""

    __tablename__ = "grievance_tickets"
    __consent_purposes__ = consent_purposes_for("customer_support")

    id = Column(Integer, primary_key=True)
    principal_id = Column(Integer, ForeignKey("data_principals.id"), nullable=False)
    summary = Column(String(200), nullable=False)
    detail = Column(EncryptedString(4096))
    status = Column(String(32), nullable=False, default="open")
    respond_by = Column(DateTime, nullable=False)
    resolved_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, default=now_utc)
    retain_until = Column(DateTime, nullable=False)


class BreachIncident(Base):
    """A personal data breach and the two intimations section 8(6) requires."""

    __tablename__ = "breach_incidents"

    id = Column(Integer, primary_key=True)
    summary = Column(String(300), nullable=False)
    severity = Column(String(16), nullable=False, default="medium")
    status = Column(String(32), nullable=False, default="open")
    records_affected = Column(Integer, nullable=False, default=0)
    detected_at = Column(DateTime, nullable=False, default=now_utc)
    notify_by = Column(DateTime, nullable=False)
    board_notified_at = Column(DateTime)
    principals_notified_at = Column(DateTime)
    retain_until = Column(DateTime, nullable=False)


class AuditLogEntry(Base):
    """Who read or changed personal data, when, and for which purpose.

    Section 8(1) puts the burden of showing compliance on the fiduciary, so the
    read side is logged as well as the write side.
    """

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    actor_principal_id = Column(Integer)
    action = Column(String(64), nullable=False)
    object_ref = Column(String(128), nullable=False)
    purpose = Column(String(64), nullable=False)
    occurred_at = Column(DateTime, nullable=False, default=now_utc)


class ExportedReport(Base):
    """A generated compliance or operations extract."""

    __tablename__ = "exported_reports"
    __consent_purposes__ = consent_purposes_for("compliance_record")

    id = Column(Integer, primary_key=True)
    report_key = Column(String(64), nullable=False)
    purpose = Column(String(64), nullable=False)
    requested_by_email = Column(EncryptedString(512))
    row_count = Column(Integer, nullable=False, default=0)
    storage_path = Column(String(512))
    generated_at = Column(DateTime, nullable=False, default=now_utc)


class AnalyticsRollup(Base):
    """Daily counters written only for accounts that opted in to analytics."""

    __tablename__ = "analytics_rollup"

    id = Column(Integer, primary_key=True)
    day = Column(Date, nullable=False)
    purpose = Column(String(64), nullable=False, default="analytics")
    event_key = Column(String(64), nullable=False)
    event_count = Column(Integer, nullable=False, default=0)
    principal_ref = Column(String(64))


class MailOutbox(Base):
    """Queued mail. Nothing leaves the machine in this fixture."""

    __tablename__ = "mail_outbox"
    __consent_purposes__ = consent_purposes_for("marketing")

    id = Column(Integer, primary_key=True)
    recipient_email = Column(EncryptedString(512), nullable=False)
    purpose = Column(String(64), nullable=False)
    summary = Column(String(200), nullable=False)
    body = Column(Text)
    queued_at = Column(DateTime, nullable=False, default=now_utc)
    sent_at = Column(DateTime)
    retain_until = Column(DateTime, nullable=False)


class Product(Base):
    """Catalogue row. No personal data."""

    __tablename__ = "products"

    id = Column(Integer, primary_key=True)
    sku = Column(String(32), nullable=False, unique=True)
    display_label = Column(String(160), nullable=False)
    price_paise = Column(Integer, nullable=False, default=0)
    tax_rate_percent = Column(Integer, nullable=False, default=18)


class Order(Base):
    """A placed order and where it has to be delivered."""

    __tablename__ = "orders"
    __consent_purposes__ = consent_purposes_for("order_fulfilment")

    id = Column(Integer, primary_key=True)
    principal_id = Column(Integer, ForeignKey("data_principals.id"), nullable=False)
    sku = Column(String(32), nullable=False)
    total_paise = Column(Integer, nullable=False, default=0)
    delivery_address = Column(EncryptedString(1024), nullable=False)
    status = Column(String(32), nullable=False, default="placed")
    placed_at = Column(DateTime, nullable=False, default=now_utc)
    retain_until = Column(DateTime, nullable=False)


_engine = create_engine(f"sqlite+pysqlite:///{DATABASE_FILE}", future=True)
SessionFactory = sessionmaker(bind=_engine, future=True, expire_on_commit=False)


def open_session():
    """A unit of work. Callers close it, the request teardown guarantees it."""
    return SessionFactory()


def create_schema() -> None:
    Base.metadata.create_all(_engine)
