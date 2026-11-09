"""Tests for URL validation service."""
import pytest
from app.services.url_validator import URLValidator


class TestURLValidation:
    """Test URL syntax and format validation."""

    def test_valid_https_url(self):
        is_valid, normalized, warnings = URLValidator.validate("https://www.google.com")
        assert is_valid is True
        assert "google.com" in normalized

    def test_valid_http_url(self):
        is_valid, normalized, warnings = URLValidator.validate("http://example.com")
        assert is_valid is True

    def test_url_without_scheme_gets_https(self):
        is_valid, normalized, warnings = URLValidator.validate("www.example.com")
        assert is_valid is True
        assert normalized.startswith("https://")

    def test_empty_url_rejected(self):
        is_valid, _, _ = URLValidator.validate("")
        assert is_valid is False

    def test_none_url_rejected(self):
        is_valid, _, _ = URLValidator.validate(None)
        assert is_valid is False

    def test_ftp_protocol_rejected(self):
        is_valid, _, _ = URLValidator.validate("ftp://files.example.com")
        assert is_valid is False

    def test_javascript_protocol_rejected(self):
        is_valid, _, _ = URLValidator.validate("javascript:alert(1)")
        assert is_valid is False

    def test_data_protocol_rejected(self):
        is_valid, _, _ = URLValidator.validate("data:text/html,<script>alert(1)</script>")
        assert is_valid is False

    def test_malformed_url_rejected(self):
        is_valid, _, _ = URLValidator.validate("not a valid url at all")
        assert is_valid is False

    def test_url_with_port(self):
        is_valid, normalized, _ = URLValidator.validate("https://example.com:8080/path")
        assert is_valid is True

    def test_url_with_query_params(self):
        is_valid, normalized, _ = URLValidator.validate("https://example.com/search?q=test&page=1")
        assert is_valid is True

    def test_url_with_fragment(self):
        is_valid, normalized, _ = URLValidator.validate("https://example.com/page#section")
        assert is_valid is True

    def test_url_with_path(self):
        is_valid, normalized, _ = URLValidator.validate("https://example.com/path/to/resource")
        assert is_valid is True

    def test_very_long_url_warning(self):
        long_url = "https://example.com/" + "a" * 2048
        is_valid, _, warnings = URLValidator.validate(long_url)
        # Should still be valid but may have a warning
        assert is_valid is True
        assert any("long" in w.lower() or "length" in w.lower() for w in warnings)


class TestSSRFProtection:
    """Test SSRF protection against private/internal IPs."""

    def test_localhost_rejected(self):
        is_valid, _, _ = URLValidator.validate("http://localhost")
        assert is_valid is False

    def test_localhost_with_port_rejected(self):
        is_valid, _, _ = URLValidator.validate("http://localhost:8080")
        assert is_valid is False

    def test_127_0_0_1_rejected(self):
        is_valid, _, _ = URLValidator.validate("http://127.0.0.1")
        assert is_valid is False

    def test_127_ip_range_rejected(self):
        is_valid, _, _ = URLValidator.validate("http://127.0.0.2")
        assert is_valid is False

    def test_10_x_private_rejected(self):
        is_valid, _, _ = URLValidator.validate("http://10.0.0.1")
        assert is_valid is False

    def test_172_16_private_rejected(self):
        is_valid, _, _ = URLValidator.validate("http://172.16.0.1")
        assert is_valid is False

    def test_192_168_private_rejected(self):
        is_valid, _, _ = URLValidator.validate("http://192.168.1.1")
        assert is_valid is False

    def test_169_254_link_local_rejected(self):
        is_valid, _, _ = URLValidator.validate("http://169.254.169.254")
        assert is_valid is False

    def test_0_0_0_0_rejected(self):
        is_valid, _, _ = URLValidator.validate("http://0.0.0.0")
        assert is_valid is False


class TestSuspiciousPatterns:
    """Test detection of suspicious URL patterns."""

    def test_ip_based_url_warning(self):
        is_valid, _, warnings = URLValidator.validate("https://93.184.216.34/page")
        assert is_valid is True
        assert any("ip" in w.lower() for w in warnings)

    def test_url_shortener_warning(self):
        is_valid, _, warnings = URLValidator.validate("https://bit.ly/abc123")
        assert is_valid is True
        assert any("shortener" in w.lower() for w in warnings)

    def test_suspicious_tld_warning(self):
        is_valid, _, warnings = URLValidator.validate("https://free-prizes.xyz")
        assert is_valid is True
        assert any("tld" in w.lower() or "suspicious" in w.lower() for w in warnings)

    def test_excessive_subdomains_warning(self):
        is_valid, _, warnings = URLValidator.validate(
            "https://a.b.c.d.e.f.example.com"
        )
        assert is_valid is True
        assert any("subdomain" in w.lower() for w in warnings)

    def test_at_sign_in_url_warning(self):
        is_valid, _, warnings = URLValidator.validate("https://google.com@evil.com")
        assert is_valid is True
        assert any("@" in w or "misleading" in w.lower() for w in warnings)

    def test_misleading_domain_warning(self):
        is_valid, _, warnings = URLValidator.validate("https://login.secure.bank.example.xyz")
        assert is_valid is True
        assert len(warnings) > 0  # Should detect suspicious patterns

    def test_clean_url_no_warnings(self):
        is_valid, _, warnings = URLValidator.validate("https://www.github.com")
        assert is_valid is True
        assert len(warnings) == 0
