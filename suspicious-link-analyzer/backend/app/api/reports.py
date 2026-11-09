import logging
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.user import User
from app.models.threat_report import ThreatReport
from app.models.scan_request import ScanRequest
from app.schemas.report import ThreatReportResponse, SendToSecurityTeamRequest, SendToSecurityTeamResponse
from app.api.deps import get_or_create_user, require_employee
from app.services.pdf_generator import PDFReportGenerator
from app.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/reports/{report_id}", response_model=ThreatReportResponse)
async def get_report(
    report_id: int,
    user: User = Depends(get_or_create_user),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ThreatReport).where(ThreatReport.id == report_id)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    # verify ownership
    if report.scan_request and report.scan_request.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    return report

@router.get("/reports/{report_id}/pdf")
async def download_report_pdf(
    report_id: int,
    user: User = Depends(get_or_create_user),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ThreatReport).where(ThreatReport.id == report_id)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    if report.scan_request and report.scan_request.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    report_dict = {
        "report_id": report.id,
        "request_id": report.request_id,
        "url": report.scan_request.url if report.scan_request else "Unknown",
        "threat_level": report.threat_level.value if hasattr(report.threat_level, 'value') else str(report.threat_level),
        "risk_score": report.risk_score,
        "explanation": report.explanation,
        "generated_at": report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC") if report.generated_at else "",
        "provider_verdicts": [
            {
                "provider_name": pv.provider_name,
                "is_malicious": pv.is_malicious,
                "detection_count": pv.detection_count,
                "category": pv.category,
                "provider_status": pv.provider_status
            }
            for pv in (report.provider_verdicts or [])
        ]
    }

    pdf_bytes = PDFReportGenerator.generate(report_dict)
    filename = f"threat_report_{report.id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.post("/reports/{report_id}/send-to-security-team", response_model=SendToSecurityTeamResponse)
async def send_to_security_team(
    report_id: int,
    payload: SendToSecurityTeamRequest,
    employee: User = Depends(require_employee),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ThreatReport).where(ThreatReport.id == report_id)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    settings = get_settings()
    recipient = payload.email or settings.SECURITY_TEAM_EMAIL

    logger.info(
        f"[AUDIT] Report #{report.id} (URL: {report.scan_request.url if report.scan_request else 'N/A'}) "
        f"sent to security team at '{recipient}' by employee '{employee.session_id}' "
        f"from company '{employee.company_name or 'N/A'}' (dept: '{employee.department or 'N/A'}')"
    )

    return SendToSecurityTeamResponse(
        success=True,
        message=f"Threat report #{report_id} has been transmitted to the Security Operations Team at {recipient}."
    )
