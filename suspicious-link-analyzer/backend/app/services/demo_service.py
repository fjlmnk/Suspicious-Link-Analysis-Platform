import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_request import ScanRequest as ScanRequestModel
from app.models.threat_report import ThreatReport as ThreatReportModel
from app.models.provider_verdict import ProviderVerdict as ProviderVerdictModel
from app.models.enums import ScanStatus, ThreatLevel
from app.services.providers.base import ProviderVerdictResult
from app.services.threat_analyzer import ThreatAnalyzer

DEMO_SCENARIOS = [
    {
        "id": "safe",
        "name": "Legitimate Search Engine (Safe)",
        "url": "https://www.google.com",
        "description": "Standard legitimate domain with clean reputation across all intelligence feeds.",
        "expected_threat_level": "SAFE",
        "verdicts": [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="clean (0/72 engines)",
                provider_status="SUCCESS"
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS"
            )
        ],
        "warnings": []
    },
    {
        "id": "suspicious",
        "name": "Newly Registered Suspicious Domain",
        "url": "https://verify-account-update.xyz/login",
        "description": "Domain using suspicious TLD and keywords typical in credential harvesting.",
        "expected_threat_level": "SUSPICIOUS",
        "verdicts": [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=2,
                category="suspicious (2/72 engines)",
                provider_status="SUCCESS"
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS"
            )
        ],
        "warnings": ["Suspicious top-level domain (.xyz) frequently abused for phishing", "Suspicious login/account keywords in subdomain"]
    },
    {
        "id": "phishing",
        "name": "Confirmed Banking Phishing URL",
        "url": "https://secure-bank-login.phishing.example.com",
        "description": "Actively identified phishing portal masquerading as financial institution login.",
        "expected_threat_level": "DANGEROUS",
        "verdicts": [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=True,
                detection_count=24,
                category="phishing (24/72 engines)",
                provider_status="SUCCESS"
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=True,
                detection_count=1,
                category="SOCIAL_ENGINEERING",
                provider_status="SUCCESS"
            )
        ],
        "warnings": ["Deceptive domain structure mimicking financial entity"]
    },
    {
        "id": "malware",
        "name": "Malware Distribution Server",
        "url": "https://download-free-software.malware.example.com",
        "description": "Known payload delivery point distributing malicious trojans or ransomware.",
        "expected_threat_level": "DANGEROUS",
        "verdicts": [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=True,
                detection_count=38,
                category="malware, trojan (38/72 engines)",
                provider_status="SUCCESS"
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=True,
                detection_count=1,
                category="MALWARE",
                provider_status="SUCCESS"
            )
        ],
        "warnings": ["Known host for unsolicited payload downloads"]
    },
    {
        "id": "conflicting",
        "name": "Conflicting Provider Responses",
        "url": "https://mixed-results.example.com",
        "description": "VirusTotal detected borderline suspicious activity, while Safe Browsing hasn't updated its feed.",
        "expected_threat_level": "SUSPICIOUS",
        "verdicts": [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=4,
                category="suspicious (4/70 engines)",
                provider_status="SUCCESS"
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS"
            )
        ],
        "warnings": ["Divergent threat intelligence verdicts"]
    },
    {
        "id": "unavailable",
        "name": "External Threat Providers Unavailable",
        "url": "https://unknown-service-edge.com",
        "description": "Simulates API timeout and rate limit outages, enforcing safe conservative fallback.",
        "expected_threat_level": "SUSPICIOUS",
        "verdicts": [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="API rate limit exceeded",
                provider_status="RATE_LIMITED"
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="Network timeout",
                provider_status="TIMEOUT"
            )
        ],
        "warnings": ["Threat intelligence providers unreachable; conservative threat verdict applied"]
    }
]

class DemoService:
    @staticmethod
    def get_scenarios() -> List[Dict[str, Any]]:
        return [
            {
                "id": s["id"],
                "name": s["name"],
                "url": s["url"],
                "description": s["description"],
                "expected_threat_level": s["expected_threat_level"]
            }
            for s in DEMO_SCENARIOS
        ]

    @staticmethod
    async def run_scenario(scenario_id: str, user_id: int, db: AsyncSession) -> ScanRequestModel:
        scenario = next((s for s in DEMO_SCENARIOS if s["id"] == scenario_id), None)
        if not scenario:
            scenario = DEMO_SCENARIOS[0]

        scan_request = ScanRequestModel(
            user_id=user_id,
            url=scenario["url"],
            submitted_at=datetime.utcnow(),
            status=ScanStatus.COMPLETED,
            is_demo=True
        )
        db.add(scan_request)
        await db.flush()

        analyzer = ThreatAnalyzer(providers=[], max_timeout_sec=5)
        verdicts: List[ProviderVerdictResult] = scenario["verdicts"]
        warnings: List[str] = scenario["warnings"]

        threat_level = analyzer.aggregate_verdicts(verdicts, warnings)
        risk_score = analyzer.calculate_risk_score(verdicts, threat_level, warnings)
        base_explanation = analyzer.generate_explanation(verdicts, threat_level, risk_score, scenario["url"], warnings)
        explanation = f"[DEMO SIMULATION - NOT REAL THREAT DATA]\n{base_explanation}"

        report = ThreatReportModel(
            request_id=scan_request.id,
            threat_level=threat_level,
            risk_score=risk_score,
            explanation=explanation,
            generated_at=datetime.utcnow()
        )
        db.add(report)
        await db.flush()

        for v in verdicts:
            pv = ProviderVerdictModel(
                report_id=report.id,
                provider_name=f"{v.provider_name} (Simulated)",
                is_malicious=v.is_malicious,
                detection_count=v.detection_count,
                category=v.category,
                checked_at=v.checked_at,
                provider_status=v.provider_status,
                raw_response=json.dumps({"simulated": True, "scenario": scenario_id})
            )
            db.add(pv)

        await db.commit()
        await db.refresh(scan_request)
        return scan_request
