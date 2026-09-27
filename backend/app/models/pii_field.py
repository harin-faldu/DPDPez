import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class PIIField(Base):
    """A personal-data field discovered by the code or web scanner."""

    __tablename__ = "pii_fields"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )

    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    line_number: Mapped[int | None] = mapped_column(nullable=True)
    field_name: Mapped[str] = mapped_column(String(200), nullable=False)

    pii_category: Mapped[str] = mapped_column(String(50), nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(20), nullable=False)

    # Where it was found: db_column, form_input, function_param, api_payload
    location_kind: Mapped[str | None] = mapped_column(String(30), nullable=True)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan = relationship("Scan", back_populates="pii_fields")
