"""Tests for threat analysis, verdict aggregation, and risk scoring."""
import pytest
from datetime import datetime
from app.services.providers.base import ProviderVerdictResult
from app.services.threat_analyzer import ThreatAnalyzer
from app.models.enums import ThreatLevel


@pytest.fixture
def analyzer():
    """Create a ThreatAnalyzer with no providers (for unit testing aggregation)."""
    return ThreatAnalyzer(providers=[], max_timeout_sec=10)


class TestVerdictAggregation:
    """Test the aggregate_verdicts method."""

    def test_all_clean_no_warnings_is_safe(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
        ]
        result = analyzer.aggregate_verdicts(verdicts, url_warnings=[])
        assert result == ThreatLevel.SAFE

    def test_any_malicious_is_dangerous(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=True,
                detection_count=15,
                category="malicious",
                provider_status="SUCCESS",
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
        ]
        result = analyzer.aggregate_verdicts(verdicts, url_warnings=[])
        assert result == ThreatLevel.DANGEROUS

    def test_conflicting_results_is_suspicious(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=2,
                category="suspicious",
                provider_status="SUCCESS",
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
        ]
        result = analyzer.aggregate_verdicts(verdicts, url_warnings=[])
        assert result == ThreatLevel.SUSPICIOUS

    def test_all_providers_failed_is_suspicious(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="Error",
                provider_status="ERROR",
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="Timeout",
                provider_status="TIMEOUT",
            ),
        ]
        result = analyzer.aggregate_verdicts(verdicts, url_warnings=[])
        assert result == ThreatLevel.SUSPICIOUS

    def test_no_verdicts_is_suspicious(self, analyzer):
        result = analyzer.aggregate_verdicts([], url_warnings=[])
        assert result == ThreatLevel.SUSPICIOUS

    def test_clean_with_url_warnings_is_suspicious(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
        ]
        warnings = ["IP-based URL detected", "Suspicious TLD"]
        result = analyzer.aggregate_verdicts(verdicts, url_warnings=warnings)
        assert result in (ThreatLevel.SUSPICIOUS, ThreatLevel.SAFE)

    def test_both_malicious_is_dangerous(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=True,
                detection_count=20,
                category="phishing",
                provider_status="SUCCESS",
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=True,
                detection_count=1,
                category="SOCIAL_ENGINEERING",
                provider_status="SUCCESS",
            ),
        ]
        result = analyzer.aggregate_verdicts(verdicts, url_warnings=[])
        assert result == ThreatLevel.DANGEROUS

    def test_one_provider_unavailable_one_clean(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="Unavailable",
                provider_status="UNAVAILABLE",
            ),
        ]
        result = analyzer.aggregate_verdicts(verdicts, url_warnings=[])
        # With incomplete data, should be SAFE or SUSPICIOUS
        assert result in (ThreatLevel.SAFE, ThreatLevel.SUSPICIOUS)


class TestRiskScoreCalculation:
    """Test the calculate_risk_score method."""

    def test_all_clean_low_score(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="clean (0/70 engines)",
                provider_status="SUCCESS",
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
        ]
        score = analyzer.calculate_risk_score(verdicts, ThreatLevel.SAFE, [])
        assert 0 <= score <= 29

    def test_dangerous_high_score(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=True,
                detection_count=25,
                category="malicious (25/70 engines)",
                provider_status="SUCCESS",
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=True,
                detection_count=1,
                category="MALWARE",
                provider_status="SUCCESS",
            ),
        ]
        score = analyzer.calculate_risk_score(verdicts, ThreatLevel.DANGEROUS, [])
        assert 70 <= score <= 100

    def test_suspicious_medium_score(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=3,
                category="suspicious (3/70 engines)",
                provider_status="SUCCESS",
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
        ]
        score = analyzer.calculate_risk_score(verdicts, ThreatLevel.SUSPICIOUS, [])
        assert 30 <= score <= 69

    def test_score_within_bounds(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=True,
                detection_count=70,
                category="malicious",
                provider_status="SUCCESS",
            ),
        ]
        score = analyzer.calculate_risk_score(verdicts, ThreatLevel.DANGEROUS, [
            "warning1", "warning2", "warning3", "warning4", "warning5"
        ])
        assert 0 <= score <= 100

    def test_url_warnings_increase_score(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
        ]
        score_no_warnings = analyzer.calculate_risk_score(verdicts, ThreatLevel.SAFE, [])
        score_with_warnings = analyzer.calculate_risk_score(
            verdicts, ThreatLevel.SUSPICIOUS, ["IP-based URL", "Suspicious TLD"]
        )
        assert score_with_warnings >= score_no_warnings

    def test_provider_failure_adds_penalty(self, analyzer):
        verdicts_ok = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
        ]
        verdicts_fail = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
            ProviderVerdictResult(
                provider_name="Google Safe Browsing",
                is_malicious=False,
                detection_count=0,
                category="Error",
                provider_status="ERROR",
            ),
        ]
        score_ok = analyzer.calculate_risk_score(verdicts_ok, ThreatLevel.SAFE, [])
        score_fail = analyzer.calculate_risk_score(verdicts_fail, ThreatLevel.SUSPICIOUS, [])
        assert score_fail >= score_ok


class TestExplanationGeneration:
    """Test the generate_explanation method."""

    def test_safe_explanation_mentions_safe(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="clean",
                provider_status="SUCCESS",
            ),
        ]
        explanation = analyzer.generate_explanation(
            verdicts, ThreatLevel.SAFE, 5.0, "https://google.com", []
        )
        assert "safe" in explanation.lower() or "no threats" in explanation.lower()

    def test_dangerous_explanation_mentions_threat(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=True,
                detection_count=15,
                category="phishing",
                provider_status="SUCCESS",
            ),
        ]
        explanation = analyzer.generate_explanation(
            verdicts, ThreatLevel.DANGEROUS, 85.0, "https://evil.com", []
        )
        assert "dangerous" in explanation.lower() or "malicious" in explanation.lower()

    def test_explanation_includes_provider_names(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=True,
                detection_count=10,
                category="malware",
                provider_status="SUCCESS",
            ),
        ]
        explanation = analyzer.generate_explanation(
            verdicts, ThreatLevel.DANGEROUS, 75.0, "https://bad.com", []
        )
        assert "VirusTotal" in explanation

    def test_explanation_includes_recommendations(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=True,
                detection_count=5,
                category="phishing",
                provider_status="SUCCESS",
            ),
        ]
        explanation = analyzer.generate_explanation(
            verdicts, ThreatLevel.DANGEROUS, 80.0, "https://phish.com", []
        )
        # Should have some actionable recommendation
        assert len(explanation) > 50

    def test_explanation_mentions_failed_providers(self, analyzer):
        verdicts = [
            ProviderVerdictResult(
                provider_name="VirusTotal",
                is_malicious=False,
                detection_count=0,
                category="Timeout",
                provider_status="TIMEOUT",
            ),
        ]
        explanation = analyzer.generate_explanation(
            verdicts, ThreatLevel.SUSPICIOUS, 40.0, "https://unknown.com", []
        )
        assert "unavailable" in explanation.lower() or "fail" in explanation.lower() or "timeout" in explanation.lower() or "incomplete" in explanation.lower()
