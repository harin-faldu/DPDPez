import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import ScanStatus


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_type: Mapped[str] = mapped_column(String(10), nullable=False)
    target: Mapped[str] = mapped_column(String(1000), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.PENDING)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    overall_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    overall_grade: Mapped[str | None] = mapped_column(String(2), nullable=True)

    files_scanned: Mapped[int] = mapped_column(default=0)
    pages_crawled: Mapped[int] = mapped_column(default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    pii_fields = relationship(
        "PIIField", back_populates="scan", cascade="all, delete-orphan"
    )
    data_flow_edges = relationship(
        "DataFlowEdge", back_populates="scan", cascade="all, delete-orphan"
    )
    flow_paths = relationship(
        "PIIFlowPath", back_populates="scan", cascade="all, delete-orphan"
    )
    rule_results = relationship(
        "RuleResult", back_populates="scan", cascade="all, delete-orphan"
    )
    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
