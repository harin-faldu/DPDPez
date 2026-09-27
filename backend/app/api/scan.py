"""Scan endpoints."""

import asyncio
import logging
import shutil
import tarfile
import uuid
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import SessionLocal, get_db
from app.models import Scan, ScanStatus, ScanType
from app.pipeline import run_code_scan, run_policy_scan, run_web_scan
from app.scanner.url_guard import UnsafeURLError, validate_scan_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])


class WebScanRequest(BaseModel):
    url: str
    # A completed policy scan of the same target. Given one, stage 2 tests every
    # claim that scan recorded against what the page actually does, and writes
    # the verdict back onto it.
    policy_scan_id: uuid.UUID | None = None


class PolicyScanRequest(BaseModel):
    url: str
    # Documents the caller names directly, for a notice the crawl cannot reach.
    # A client rendered policy returns an empty shell over plain HTTP, and the
    # honest answer to that is to ask rather than to guess or to report the site
    # as publishing nothing.
    policy_urls: list[str] = []


class ScanAccepted(BaseModel):
    scan_id: uuid.UUID
    status: str


@router.post("/web", response_model=ScanAccepted, status_code=202)
async def scan_web(
    payload: WebScanRequest, db: AsyncSession = Depends(get_db)
) -> ScanAccepted:
    try:
        safe_url = validate_scan_url(payload.url)
    except UnsafeURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan = Scan(
        scan_type=ScanType.WEB, target=safe_url, status=ScanStatus.PENDING
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # A crawl takes tens of seconds, so the request returns immediately and the
    # dashboard polls. The task owns its own session because the request-scoped
    # one closes as soon as this handler returns.
    asyncio.create_task(_run_web_task(scan.id, safe_url, payload.policy_scan_id))

    return ScanAccepted(scan_id=scan.id, status=scan.status)


@router.post("/policy", response_model=ScanAccepted, status_code=202)
async def scan_policy(
    payload: PolicyScanRequest, db: AsyncSession = Depends(get_db)
) -> ScanAccepted:
    """Stage 1: read the organisation's published policies.

    Lighter than a web scan, but still tens of fetches against someone else's
    site, so it returns immediately and the dashboard polls exactly as it does
    for the other two stages.
    """
    try:
        safe_url = validate_scan_url(payload.url)
    except UnsafeURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan = Scan(scan_type=ScanType.POLICY, target=safe_url, status=ScanStatus.PENDING)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    asyncio.create_task(_run_policy_task(scan.id, safe_url, payload.policy_urls))

    return ScanAccepted(scan_id=scan.id, status=scan.status)


@router.post("/code", response_model=ScanAccepted, status_code=202)
async def scan_code(
    file: UploadFile = File(...),
    # A completed policy scan of the same target. Given one, stage 3 tries
    # every claim still not_observable after stage 2 against the code, and
    # writes the verdict back onto it.
    policy_scan_id: uuid.UUID | None = Form(None),
    db: AsyncSession = Depends(get_db),
) -> ScanAccepted:
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename supplied")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".zip", ".gz", ".tgz", ".tar"):
        raise HTTPException(
            status_code=400, detail="Upload a .zip or .tar.gz archive of the source"
        )

    scan_id = uuid.uuid4()
    workspace = Path(settings.scan_workspace_dir) / str(scan_id)
    workspace.mkdir(parents=True, exist_ok=True)
    archive_path = workspace / f"upload{suffix}"

    try:
        await _save_upload(file, archive_path)
        extract_root = workspace / "src"
        extract_root.mkdir(exist_ok=True)
        _safe_extract(archive_path, extract_root)
    except HTTPException:
        shutil.rmtree(workspace, ignore_errors=True)
        raise
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(workspace, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Could not read archive: {exc}") from exc
    finally:
        archive_path.unlink(missing_ok=True)

    scan = Scan(
        id=scan_id,
        scan_type=ScanType.CODE,
        target=file.filename,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()

    asyncio.create_task(_run_code_task(scan_id, str(extract_root), policy_scan_id))

    return ScanAccepted(scan_id=scan_id, status=ScanStatus.PENDING)


@router.get("/{scan_id}")
async def get_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> dict:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": str(scan.id),
        "scan_type": scan.scan_type,
        "target": scan.target,
        "status": scan.status,
        "overall_score": scan.overall_score,
        "overall_grade": scan.overall_grade,
        "files_scanned": scan.files_scanned,
        "pages_crawled": scan.pages_crawled,
        "error_message": scan.error_message,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }


async def _run_web_task(
    scan_id: uuid.UUID, url: str, policy_scan_id: uuid.UUID | None = None
) -> None:
    async with SessionLocal() as session:
        await run_web_scan(session, scan_id, url, policy_scan_id)


async def _run_policy_task(
    scan_id: uuid.UUID, url: str, policy_urls: list[str] | None = None
) -> None:
    async with SessionLocal() as session:
        await run_policy_scan(session, scan_id, url, policy_urls)


async def _run_code_task(
    scan_id: uuid.UUID, root: str, policy_scan_id: uuid.UUID | None = None
) -> None:
    async with SessionLocal() as session:
        await run_code_scan(session, scan_id, root, policy_scan_id)


async def _save_upload(file: UploadFile, destination: Path) -> None:
    """Stream to disk, enforcing the size cap as we go.

    Reading the whole upload into memory first would let a large file exhaust
    the process before any limit could be applied.
    """
    limit = settings.max_upload_size_mb * 1024 * 1024
    written = 0
    with destination.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            written += len(chunk)
            if written > limit:
                raise HTTPException(
                    status_code=413,
                    detail=f"Archive exceeds {settings.max_upload_size_mb} MB",
                )
            out.write(chunk)


def _is_within(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
    except ValueError:
        return False
    return True


def _safe_extract(archive: Path, destination: Path) -> None:
    """Extract, refusing members that would escape the destination.

    An archive entry named ../../etc/passwd or holding an absolute path would
    otherwise let an upload write anywhere the process can reach.
    """
    max_files = settings.max_files_per_scan
    max_total = settings.max_upload_size_mb * 1024 * 1024 * 20

    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            members = zf.infolist()
            if len(members) > max_files:
                raise HTTPException(status_code=413, detail="Archive has too many files")
            if sum(m.file_size for m in members) > max_total:
                raise HTTPException(status_code=413, detail="Archive expands too large")
            for member in members:
                target = destination / member.filename
                if Path(member.filename).is_absolute() or not _is_within(destination, target):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Archive contains an unsafe path: {member.filename}",
                    )
            zf.extractall(destination)
        return

    if tarfile.is_tarfile(archive):
        with tarfile.open(archive) as tf:
            members = tf.getmembers()
            if len(members) > max_files:
                raise HTTPException(status_code=413, detail="Archive has too many files")
            if sum(m.size for m in members) > max_total:
                raise HTTPException(status_code=413, detail="Archive expands too large")
            for member in members:
                target = destination / member.name
                if (
                    member.islnk()
                    or member.issym()
                    or Path(member.name).is_absolute()
                    or not _is_within(destination, target)
                ):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Archive contains an unsafe entry: {member.name}",
                    )
            tf.extractall(destination)
        return

    raise HTTPException(status_code=400, detail="Unrecognised archive format")
