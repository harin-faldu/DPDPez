"""Where the policy stage's output is kept.

Two tables, because the stage produces two different kinds of thing. A check is
settled by this stage: the requirement is addressed or it is not, and nothing
later changes that. A claim is deliberately unsettled, and the columns a later
stage fills are null on purpose: null means nobody has looked yet, which is a
different state from looked and found nothing.

Registered with the metadata through app.models so create_all sees them.
"""

import uuid

from sqlalchemy import Boolean, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class PolicyCheck(Base):
    """One statutory requirement read against what the site published."""

    __tablename__ = "policy_checks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )

    requirement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    dpdp_section: Mapped[str | None] = mapped_column(String(50), nullable=True)
    dpdp_rule: Mapped[str | None] = mapped_column(String(50), nullable=True)

    satisfied: Mapped[bool] = mapped_column(Boolean, default=False)
    # True where the requirement could not be looked at, so the row is neither a
    # satisfied check nor a gap. Stored rather than derived from the evidence
    # text, so a reader of the table never has to parse prose to tell them apart.
    unassessed: Mapped[bool] = mapped_column(Boolean, default=False)

    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    quote: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    requires_human_validation: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)

    scan = relationship("Scan")


class PolicyClaimRecord(Base):
    """An assertion the policy makes, waiting for a later stage to test it."""

    __tablename__ = "policy_claims"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )

    claim_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    value: Mapped[str | None] = mapped_column(String(300), nullable=True)
    # Verbatim, and a contiguous substring of the document it came from, so a
    # reviewer can find it on the page. Never carries a contact value.
    quote: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)

    # Filled by stage 2 or stage 3. Null means nobody has looked.
    verified_by: Mapped[str | None] = mapped_column(String(10), nullable=True)
    verification: Mapped[str | None] = mapped_column(String(20), nullable=True)
    verification_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan = relationship("Scan")
