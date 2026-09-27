import uuid

from pgvector.sqlalchemy import Vector
from sqlalchemy import String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.config import settings
from app.database import Base


class DPDPCorpusChunk(Base):
    """A citation-bearing chunk of the DPDP Act 2023 or DPDP Rules 2025.

    Every chunk carries its own citation_label so retrieval hands the model the
    citation directly. The model never has to infer which section it is reading,
    which is where hallucinated citations come from.
    """

    __tablename__ = "dpdp_corpus"
    __table_args__ = (UniqueConstraint("section_id", "chunk_index"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    source: Mapped[str] = mapped_column(String(20), nullable=False)
    section_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    section_title: Mapped[str] = mapped_column(String(300), nullable=False)
    citation_label: Mapped[str] = mapped_column(String(150), nullable=False)

    chunk_index: Mapped[int] = mapped_column(default=0)
    chunk_text: Mapped[str] = mapped_column(Text, nullable=False)

    embedding: Mapped[list[float] | None] = mapped_column(
        Vector(settings.gemini_embedding_dim), nullable=True
    )
