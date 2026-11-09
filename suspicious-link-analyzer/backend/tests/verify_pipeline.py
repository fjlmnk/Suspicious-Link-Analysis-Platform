"""Verification script for testing threat detection and report generation."""
import asyncio
from datetime import datetime

from app.models.enums import ThreatLevel
from app.services.threat_analyzer import ThreatAnalyzer
from app.services.providers.base import ProviderVerdictResult
from app.services.url_validator import URLValidator
from app.services.pdf_generator import PDFReportGenerator
from app.services.demo_service import DEMO_SCENARIOS


def test_pipeline():
    print("=" * 65)
    print("      SUSPICIOUS LINK ANALYZER - VERIFICATION TEST")
    print("=" * 65)

    analyzer = ThreatAnalyzer(providers=[], max_timeout_sec=5)

    # 1. Test URL Validator & SSRF Protection
    print("\n[TEST 1] Testing URL Validation & SSRF Guard...")
    safe_valid, _, warnings_safe = URLValidator.validate("https://www.google.com")
    ssrf_valid, _, ssrf_msg = URLValidator.validate("http://127.0.0.1/admin")
    short_valid, _, warnings_short = URLValidator.validate("https://bit.ly/malicious-link")

    assert safe_valid is True, "Google should be valid"
    assert ssrf_valid is False, "SSRF loopback 127.0.0.1 must be BLOCKED"
    assert short_valid is True and len(warnings_short) > 0, "URL shortener warning expected"
    print("   [+] Google validation: PASS (Clean)")
    print(f"   [+] SSRF 127.0.0.1 rejection: PASS (Blocked: {ssrf_msg[0]})")
    print(f"   [+] URL Shortener heuristic: PASS (Warning: {warnings_short[0]})")

    # 2. Test Threat Scenarios from Threat Intelligence
    print("\n[TEST 2] Testing Threat Classifications & Risk Scoring...")

    for sc in DEMO_SCENARIOS:
        sc_id = sc["id"]
        url = sc["url"]
        verdicts = sc["verdicts"]
        warnings = sc["warnings"]

        threat_level = analyzer.aggregate_verdicts(verdicts, warnings)
        risk_score = analyzer.calculate_risk_score(verdicts, threat_level, warnings)
        explanation = analyzer.generate_explanation(verdicts, threat_level, risk_score, url, warnings)

        print(f"\n   Scenario: '{sc['name']}'")
        print(f"   - Target: {url}")
        print(f"   - Detected Level: {threat_level.value}")
        print(f"   - Numerical Risk Score: {risk_score} / 100")
        print(f"   - Expected: {sc['expected_threat_level']}")

        # Verify assertions
        if sc["expected_threat_level"] == "SAFE":
            assert threat_level == ThreatLevel.SAFE
            assert risk_score < 30
        elif sc["expected_threat_level"] == "DANGEROUS":
            assert threat_level == ThreatLevel.DANGEROUS
            assert risk_score >= 70
        elif sc["expected_threat_level"] == "SUSPICIOUS":
            assert threat_level == ThreatLevel.SUSPICIOUS
            assert 30 <= risk_score <= 69

        print("   [+] Classification & Risk Score: VERIFIED")

    # 3. Test PDF Report Generation
    print("\n[TEST 3] Testing Official PDF Report Generation...")
    sample_report_data = {
        "report_id": 999,
        "request_id": 101,
        "url": "https://secure-bank-login.phishing.example.com",
        "threat_level": "DANGEROUS",
        "risk_score": 87.5,
        "explanation": "Threat detected: Confirmed Banking Phishing URL with credential harvesting attack vectors.",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "provider_verdicts": [
            {
                "provider_name": "VirusTotal",
                "is_malicious": True,
                "detection_count": 24,
                "category": "phishing",
                "provider_status": "SUCCESS"
            },
            {
                "provider_name": "Google Safe Browsing",
                "is_malicious": True,
                "detection_count": 1,
                "category": "SOCIAL_ENGINEERING",
                "provider_status": "SUCCESS"
            },
            {
                "provider_name": "URLhaus (abuse.ch)",
                "is_malicious": True,
                "detection_count": 3,
                "category": "Malware: credential_harvester",
                "provider_status": "SUCCESS"
            }
        ]
    }

    pdf_bytes = PDFReportGenerator.generate(sample_report_data)
    assert pdf_bytes.startswith(b"%PDF"), "Generated output must be a valid PDF binary"
    assert len(pdf_bytes) > 1000, "PDF file must not be empty"
    print(f"   [+] PDF Export: PASS (Successfully generated {len(pdf_bytes)} bytes of valid PDF)")

    print("\n" + "=" * 65)
    print("      ALL TESTS PASSED: THE SYSTEM DETECTS THREATS ACCURATELY!")
    print("=" * 65)


if __name__ == "__main__":
    test_pipeline()
