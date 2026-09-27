import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import findings, health, scan, scorecard
from app.config import settings

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting DPDPA Reviewer (env=%s)", settings.app_env)

    from app.database import init_db

    try:
        await init_db()
    except Exception:  # noqa: BLE001
        logger.exception("Database initialisation failed; API will report degraded")

    if not settings.ai_enabled:
        logger.warning(
            "GEMINI_API_KEY not set. Scans will run but findings will have no "
            "grounded explanation or citation."
        )
    else:
        await _index_corpus_if_needed()
    yield
    logger.info("Shutting down")


async def _index_corpus_if_needed() -> None:
    """Embed the statutory corpus so a fresh database is queryable on first run.

    Indexing failure is logged, not raised: the scanner and rules engine work
    without RAG, and refusing to boot would lose more than it protects.
    """
    from app.corpus import indexer
    from app.database import SessionLocal

    try:
        async with SessionLocal() as session:
            if await indexer.corpus_is_indexed(session):
                logger.info("DPDP corpus already indexed")
                return
            written = await indexer.index_corpus(session)
            logger.info("Indexed %d DPDP corpus chunks", written)
    except Exception:  # noqa: BLE001
        logger.exception("Corpus indexing failed; findings will fall back to no citation")


app = FastAPI(
    title="DPDPA Compliance Self-Check",
    description=(
        "Scans a web form or a codebase and produces a DPDP Act 2023 compliance "
        "scorecard. Verdicts are deterministic; AI supplies explanation and "
        "statutory citation only."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api")
app.include_router(scan.router, prefix="/api")
app.include_router(findings.router, prefix="/api")
app.include_router(scorecard.router, prefix="/api")
