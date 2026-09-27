"""Embed the corpus into pgvector.  OWNER: Prerana (with Aryan on the AI call)

Run once at startup or from a CLI. Without this the RAG layer has nothing to
retrieve and every finding falls back to an unexplained verdict.
"""

import logging
from itertools import batched

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import gateway
from app.corpus.chunker import StatutoryChunk, build_chunks
from app.models import DPDPCorpusChunk

logger = logging.getLogger(__name__)

# The embedding endpoint takes many inputs per call. Batching keeps a cold boot
# to a couple of requests instead of one per chunk.
EMBED_BATCH_SIZE = 50

# Corpus chunks are documents, not queries. Embedding them as "retrieval_query"
# would put them in a different space from retrieval.retrieve_provisions, which
# embeds the query side, and recall would quietly collapse.
_TASK_TYPE = "retrieval_document"


def _embedding_input(chunk: StatutoryChunk) -> str:
    """What gets embedded, which is deliberately not what gets stored.

    The citation label and section title go into the vector so a query naming a
    provision ("Section 8(5) security safeguards") lands on it. They stay out of
    chunk_text, because chunk_text is what the guardrail verifies quotes
    against and it has to stay purely statutory.
    """
    return f"{chunk.citation_label} ({chunk.section_title}): {chunk.text}"


async def index_corpus(db: AsyncSession, *, force: bool = False) -> int:
    """Embed every chunk and upsert into dpdp_corpus. Returns rows written."""
    chunks = build_chunks()

    rows = (await db.execute(select(DPDPCorpusChunk))).scalars().all()
    existing = {(r.section_id, r.chunk_index): r for r in rows}

    # Drop rows the corpus no longer produces. A stale row keeps its embedding
    # and stays retrievable, which would let the tool cite text that is no
    # longer in the corpus the guardrail checks citations against.
    current_keys = {(c.section_id, c.chunk_index) for c in chunks}
    stale = [row for key, row in existing.items() if key not in current_keys]
    for row in stale:
        await db.delete(row)
    if stale:
        logger.info("Removing %d stale corpus rows", len(stale))

    pending: list[tuple[StatutoryChunk, DPDPCorpusChunk | None]] = []
    for chunk in chunks:
        row = existing.get((chunk.section_id, chunk.chunk_index))
        if row is not None and row.embedding is not None and not force:
            continue
        pending.append((chunk, row))

    if not pending:
        if stale:
            await db.commit()
        logger.info("Corpus already embedded, nothing to do")
        return 0

    written = 0
    for batch in batched(pending, EMBED_BATCH_SIZE):
        vectors = await gateway.embed_batch(
            [_embedding_input(chunk) for chunk, _ in batch],
            task_type=_TASK_TYPE,
        )
        if len(vectors) != len(batch):
            raise RuntimeError(
                f"embed_batch returned {len(vectors)} vectors for {len(batch)} chunks"
            )

        for (chunk, row), vector in zip(batch, vectors):
            if row is None:
                db.add(
                    DPDPCorpusChunk(
                        source=chunk.source,
                        section_id=chunk.section_id,
                        section_title=chunk.section_title,
                        citation_label=chunk.citation_label,
                        chunk_index=chunk.chunk_index,
                        chunk_text=chunk.text,
                        embedding=vector,
                    )
                )
            else:
                row.source = chunk.source
                row.section_title = chunk.section_title
                row.citation_label = chunk.citation_label
                row.chunk_text = chunk.text
                row.embedding = vector
            written += 1

    await db.commit()
    logger.info("Embedded %d of %d corpus chunks", written, len(chunks))
    return written


async def corpus_is_indexed(db: AsyncSession) -> bool:
    """True when at least one chunk has an embedding."""
    stmt = (
        select(DPDPCorpusChunk.id)
        .where(DPDPCorpusChunk.embedding.is_not(None))
        .limit(1)
    )
    return (await db.execute(stmt)).first() is not None
