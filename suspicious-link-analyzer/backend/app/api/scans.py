import asyncio
import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.database import get_db, async_session_maker
from app.models.user import User
from app.models.scan_request import ScanRequest
from app.models.threat_report import ThreatReport
from app.models.enums import ScanStatus, ThreatLevel
from app.schemas.scan import ScanCreate, ScanResponse, ScanHistoryResponse
from app.api.deps import get_or_create_user
from app.config import get_settings
from app.services.threat_analyzer import ThreatAnalyzer
from app.services.providers.virustotal import VirusTotalProvider
from app.services.providers.safebrowsing import SafeBrowsingProvider
from app.services.providers.urlhaus import URLhausProvider
from app.services.url_validator import URLValidator

logger = logging.getLogger(__name__)
router = APIRouter()

def get_threat_analyzer() -> ThreatAnalyzer:
    settings = get_settings()
    vt_provider = VirusTotalProvider(
        api_key=settings.VIRUSTOTAL_API_KEY,
        api_endpoint=settings.VIRUSTOTAL_ENDPOINT,
        daily_request_limit=settings.VIRUSTOTAL_DAILY_LIMIT,
    )
    sb_provider = SafeBrowsingProvider(
        api_key=settings.SAFEBROWSING_API_KEY,
        api_endpoint=settings.SAFEBROWSING_ENDPOINT,
        daily_request_limit=settings.SAFEBROWSING_DAILY_LIMIT,
    )
    urlhaus_provider = URLhausProvider(
        api_key=settings.URLHAUS_API_KEY,
        api_endpoint=settings.URLHAUS_ENDPOINT,
        daily_request_limit=settings.URLHAUS_DAILY_LIMIT,
    )
    return ThreatAnalyzer(
        providers=[vt_provider, sb_provider, urlhaus_provider],
        max_timeout_sec=settings.SCAN_TIMEOUT_SEC,
    )

async def run_scan_background(scan_id: int):
    async with async_session_maker() as session:
        try:
            analyzer = get_threat_analyzer()
            await analyzer.analyze(scan_id, session)
        except Exception as e:
            logger.exception(f"Error during scan #{scan_id}: {e}")
            stmt = select(ScanRequest).where(ScanRequest.id == scan_id)
            res = await session.execute(stmt)
            req = res.scalar_one_or_none()
            if req:
                req.status = ScanStatus.FAILED
                await session.commit()

@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def submit_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_or_create_user),
    db: AsyncSession = Depends(get_db),
):
    is_valid, normalized_url, _ = URLValidator.validate(payload.url)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL or target disallowed by security policy (SSRF protection)."
        )

    scan_req = ScanRequest(
        user_id=user.id,
        url=normalized_url,
        status=ScanStatus.PENDING,
        is_demo=False,
        submitted_at=datetime.utcnow()
    )
    db.add(scan_req)
    await db.commit()
    await db.refresh(scan_req)

    background_tasks.add_task(run_scan_background, scan_req.id)
    return scan_req

@router.get("/scans/history", response_model=ScanHistoryResponse)
async def get_scan_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    status_filter: Optional[ScanStatus] = Query(None, alias="status"),
    threat_level: Optional[ThreatLevel] = Query(None),
    user: User = Depends(get_or_create_user),
    db: AsyncSession = Depends(get_db)
):
    query = select(ScanRequest).where(ScanRequest.user_id == user.id)

    if status_filter:
        query = query.where(ScanRequest.status == status_filter)

    if threat_level:
        query = query.join(ScanRequest.threat_report).where(ThreatReport.threat_level == threat_level)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_res = await db.execute(count_query)
    total = total_res.scalar_one()

    # Apply pagination and sorting
    query = query.order_by(desc(ScanRequest.submitted_at)).offset((page - 1) * page_size).limit(page_size)
    items_res = await db.execute(query)
    items = items_res.scalars().all()

    return ScanHistoryResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size
    )

@router.get("/scans/{request_id}", response_model=ScanResponse)
async def get_scan(
    request_id: int,
    user: User = Depends(get_or_create_user),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ScanRequest).where(ScanRequest.id == request_id)
    res = await db.execute(stmt)
    scan_req = res.scalar_one_or_none()

    if not scan_req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan request not found")

    if scan_req.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    return scan_req

@router.get("/scans/{request_id}/report", response_model=ScanResponse)
async def get_scan_report(
    request_id: int,
    user: User = Depends(get_or_create_user),
    db: AsyncSession = Depends(get_db),
):
    return await get_scan(request_id, user, db)
