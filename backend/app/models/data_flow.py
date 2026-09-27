import uuid

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class DataFlowEdge(Base):
    """One directed edge in the code graph: a symbol reaching another symbol."""

    __tablename__ = "data_flow_edges"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )

    source_file: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source_line: Mapped[int | None] = mapped_column(nullable=True)
    source_symbol: Mapped[str | None] = mapped_column(String(200), nullable=True)

    sink_file: Mapped[str | None] = mapped_column(String(500), nullable=True)
    sink_line: Mapped[int | None] = mapped_column(nullable=True)
    sink_symbol: Mapped[str | None] = mapped_column(String(200), nullable=True)

    edge_type: Mapped[str] = mapped_column(String(30), nullable=False)
    pii_categories: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(50)), nullable=True
    )

    scan = relationship("Scan", back_populates="data_flow_edges")


class PIIFlowPath(Base):
    """End-to-end lifecycle of one PII category: source through transforms to sink."""

    __tablename__ = "pii_flow_paths"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )

    pii_category: Mapped[str] = mapped_column(String(50), nullable=False)
    source_description: Mapped[str] = mapped_column(Text, nullable=False)
    transforms: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    sink_description: Mapped[str] = mapped_column(Text, nullable=False)

    has_consent_check: Mapped[bool] = mapped_column(Boolean, default=False)
    has_encryption: Mapped[bool] = mapped_column(Boolean, default=False)
    has_retention_policy: Mapped[bool] = mapped_column(Boolean, default=False)
    crosses_third_party: Mapped[bool] = mapped_column(Boolean, default=False)

    scan = relationship("Scan", back_populates="flow_paths")
