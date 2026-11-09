import asyncio
import json
import logging
from datetime import datetime
from typing import List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.scan_request import ScanRequest as ScanRequestModel
from app.models.threat_report import ThreatReport as ThreatReportModel
from app.models.provider_verdict import ProviderVerdict as ProviderVerdictModel
from app.models.enums import ScanStatus, ThreatLevel
from app.services.providers.base import ThreatDataProvider, ProviderVerdictResult
from app.services.url_validator import URLValidator

logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    def __init__(self, providers: List[ThreatDataProvider], max_timeout_sec: int = 30):
        self.providers = providers
        self.max_timeout_sec = max_timeout_sec

    async def analyze(self, scan_request_id: int, db: AsyncSession) -> Optional[ThreatReportModel]:
        stmt = select(ScanRequestModel).where(ScanRequestModel.id == scan_request_id)
        res = await db.execute(stmt)
        request = res.scalar_one_or_none()
        if not request:
            logger.error(f"ScanRequest #{scan_request_id} not found")
            return None

        # 1. Validate URL
        is_valid, normalized_url, warnings = URLValidator.validate(request.url)
        if not is_valid:
            request.status = ScanStatus.FAILED
            await db.commit()
            return None

        # 2. Query providers concurrently
        provider_tasks = [provider.check_url(normalized_url) for provider in self.providers]
        try:
            verdict_results: List[ProviderVerdictResult] = await asyncio.wait_for(
                asyncio.gather(*provider_tasks, return_exceptions=True),
                timeout=float(self.max_timeout_sec)
            )
        except asyncio.TimeoutError:
            verdict_results = [
                ProviderVerdictResult(
                    provider_name=p.name,
                    is_malicious=False,
                    category="Timeout during analysis",
                    provider_status="TIMEOUT"
                )
                for p in self.providers
            ]

        # Handle exceptions in gathered tasks
        clean_results: List[ProviderVerdictResult] = []
        for idx, res in enumerate(verdict_results):
            if isinstance(res, Exception):
                clean_results.append(
                    ProviderVerdictResult(
                        provider_name=self.providers[idx].name,
                        is_malicious=False,
                        category=f"Provider error: {str(res)[:100]}",
                        provider_status="ERROR"
                    )
                )
            else:
                clean_results.append(res)

        # 3. Aggregate verdicts & calculate risk score
        threat_level = self.aggregate_verdicts(clean_results, warnings)
        risk_score = self.calculate_risk_score(clean_results, threat_level, warnings)
        explanation = self.generate_explanation(clean_results, threat_level, risk_score, normalized_url, warnings)

        # 4. Save ThreatReport
        report = ThreatReportModel(
            request_id=request.id,
            threat_level=threat_level,
            risk_score=risk_score,
            explanation=explanation,
            generated_at=datetime.utcnow()
        )
        db.add(report)
        await db.flush()

        # 5. Save ProviderVerdicts
        for vr in clean_results:
            pv = ProviderVerdictModel(
                report_id=report.id,
                provider_name=vr.provider_name,
                is_malicious=vr.is_malicious,
                detection_count=vr.detection_count,
                category=vr.category,
                checked_at=vr.checked_at,
                provider_status=vr.provider_status,
                raw_response=vr.raw_response
            )
            db.add(pv)

        request.status = ScanStatus.COMPLETED
        await db.commit()
        await db.refresh(report)
        return report

    def aggregate_verdicts(self, verdicts: List[ProviderVerdictResult], url_warnings: List[str]) -> ThreatLevel:
        if not verdicts:
            return ThreatLevel.SUSPICIOUS

        has_malicious = any(v.is_malicious for v in verdicts)
        if has_malicious:
            return ThreatLevel.DANGEROUS

        # Check if all providers failed or timed out
        all_failed = all(v.provider_status in ("ERROR", "TIMEOUT", "UNAVAILABLE", "RATE_LIMITED") for v in verdicts)
        if all_failed:
            return ThreatLevel.SUSPICIOUS

        has_suspicious_engine = any("suspicious" in (v.category or "").lower() for v in verdicts)
        if has_suspicious_engine or len(url_warnings) >= 2:
            return ThreatLevel.SUSPICIOUS

        if len(url_warnings) == 1:
            return ThreatLevel.SUSPICIOUS

        # If some providers succeeded and none detected malicious
        any_success = any(v.provider_status == "SUCCESS" for v in verdicts)
        if any_success and not url_warnings:
            return ThreatLevel.SAFE

        return ThreatLevel.SUSPICIOUS

    def calculate_risk_score(self, verdicts: List[ProviderVerdictResult], 
                             threat_level: ThreatLevel, url_warnings: List[str]) -> float:
        score = 0.0

        for v in verdicts:
            if v.provider_name == "VirusTotal":
                if v.is_malicious:
                    # vt ratio weight up to 40
                    score += min(40.0, 15.0 + v.detection_count * 2.5)
                elif "suspicious" in (v.category or "").lower():
                    score += min(20.0, 5.0 + v.detection_count * 3.0)
            elif "Google Safe Browsing" in v.provider_name:
                if v.is_malicious:
                    score += 30.0

            if v.provider_status in ("ERROR", "TIMEOUT", "UNAVAILABLE"):
                score += 7.5

        # Warnings contribution (0-15)
        score += min(15.0, len(url_warnings) * 5.0)

        # Baseline alignment with threat_level
        if threat_level == ThreatLevel.DANGEROUS:
            score = max(score, 75.0)
        elif threat_level == ThreatLevel.SUSPICIOUS:
            score = max(30.0, min(score, 68.0))
        elif threat_level == ThreatLevel.SAFE:
            score = min(score, 25.0)

        return round(min(100.0, max(0.0, score)), 1)

    def generate_explanation(self, verdicts: List[ProviderVerdictResult],
                             threat_level: ThreatLevel, risk_score: float,
                             url: str, url_warnings: List[str]) -> str:
        parts = []
        if threat_level == ThreatLevel.SAFE:
            parts.append(f"The URL '{url}' has been analyzed and classified as SAFE with a low risk score of {risk_score}/100.")
            parts.append("None of the threat intelligence engines reported known malicious behavior, phishing, or malware distribution.")
        elif threat_level == ThreatLevel.DANGEROUS:
            parts.append(f"WARNING: The URL '{url}' has been classified as DANGEROUS with a high risk score of {risk_score}/100!")
            parts.append("Threat intelligence providers have detected active security threats, such as phishing, malware delivery, or social engineering.")
        else:
            parts.append(f"Caution advised: The URL '{url}' has been classified as SUSPICIOUS with a risk score of {risk_score}/100.")
            parts.append("Indicators of risk were detected or provider data was incomplete/conflicting.")

        # Provider details
        parts.append("\nProvider Findings:")
        for v in verdicts:
            status_desc = f"{v.provider_name}: [{v.provider_status}] - "
            if v.is_malicious:
                status_desc += f"MALICIOUS detected ({v.detection_count} flags, {v.category})"
            elif v.provider_status == "SUCCESS":
                status_desc += f"Clean ({v.category or 'No threats'})"
            else:
                status_desc += f"Incomplete result ({v.category})"
            parts.append(f"- {status_desc}")

        if url_warnings:
            parts.append("\nStructural URL Warnings:")
            for w in url_warnings:
                parts.append(f"- {w}")

        parts.append("\nSecurity Recommendations:")
        if threat_level == ThreatLevel.DANGEROUS:
            parts.append("1. DO NOT open this URL or submit credentials.")
            parts.append("2. Block access on your corporate network / DNS firewall.")
            parts.append("3. Report this incident to your security operations team.")
        elif threat_level == ThreatLevel.SUSPICIOUS:
            parts.append("1. Exercise extreme caution before accessing this link.")
            parts.append("2. Verify the sender or domain authenticity through an independent channel.")
            parts.append("3. Avoid entering passwords, personal information, or banking details.")
        else:
            parts.append("1. Link appears benign according to current threat intelligence databases.")
            parts.append("2. Always practice general web safety and check SSL certificate validity.")

        return "\n".join(parts)
