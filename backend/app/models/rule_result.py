import uuid

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class RuleResult(Base):
    """Deterministic verdict for one DPDP rule. Produced by the rules engine only."""

    __tablename__ = "rule_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )

    rule_id: Mapped[str] = mapped_column(String(10), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(100), nullable=False)

    status: Mapped[str] = mapped_column(String(20), nullable=False)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    weight: Mapped[float] = mapped_column(Float, default=0.0)

    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    checks_passed: Mapped[int] = mapped_column(default=0)
    checks_total: Mapped[int] = mapped_column(default=0)

    dpdp_section: Mapped[str | None] = mapped_column(String(50), nullable=True)
    dpdp_rule: Mapped[str | None] = mapped_column(String(50), nullable=True)

    scan = relationship("Scan", back_populates="rule_results")
