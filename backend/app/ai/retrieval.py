"""pgvector retrieval over the DPDP statutory corpus."""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import gateway
from app.config import settings
from app.contracts import RetrievedProvision
from app.models import DPDPCorpusChunk

logger = logging.getLogger(__name__)


async def retrieve_provisions(
    db: AsyncSession,
    query_text: str,
    *,
    top_k: int | None = None,
    restrict_section_ids: list[str] | None = None,
) -> list[RetrievedProvision]:
    """Find the statutory provisions most similar to query_text.

    restrict_section_ids pins retrieval to the sections a rule is actually about,
    so a Rule 6 finding cannot retrieve and then cite Rule 9.
    """
    k = top_k or settings.rag_top_k

    try:
        query_vector = await gateway.embed(query_text, task_type="retrieval_query")
    except gateway.AIUnavailableError:
        logger.info("AI disabled, skipping retrieval")
        return []
    except Exception:  # noqa: BLE001 - retrieval failure must not fail the scan
        logger.exception("Embedding failed during retrieval")
        return []

    distance = DPDPCorpusChunk.embedding.cosine_distance(query_vector)
    stmt = (
        select(DPDPCorpusChunk, distance.label("distance"))
        .where(DPDPCorpusChunk.embedding.is_not(None))
        .order_by(distance)
        .limit(k)
    )
    if restrict_section_ids:
        stmt = stmt.where(DPDPCorpusChunk.section_id.in_(restrict_section_ids))

    rows = (await db.execute(stmt)).all()

    provisions: list[RetrievedProvision] = []
    for chunk, dist in rows:
        similarity = 1.0 - float(dist)
        if similarity < settings.rag_min_similarity:
            continue
        provisions.append(
            RetrievedProvision(
                section_id=chunk.section_id,
                citation_label=chunk.citation_label,
                section_title=chunk.section_title,
                text=chunk.chunk_text,
                similarity=round(similarity, 4),
            )
        )
    return provisions


async def fetch_by_section_ids(
    db: AsyncSession, section_ids: list[str]
) -> list[RetrievedProvision]:
    """Exact lookup, no embedding. Used to seed retrieval when AI is unavailable."""
    if not section_ids:
        return []
    stmt = select(DPDPCorpusChunk).where(DPDPCorpusChunk.section_id.in_(section_ids))
    chunks = (await db.execute(stmt)).scalars().all()
    return [
        RetrievedProvision(
            section_id=c.section_id,
            citation_label=c.citation_label,
            section_title=c.section_title,
            text=c.chunk_text,
            similarity=1.0,
        )
        for c in chunks
    ]
