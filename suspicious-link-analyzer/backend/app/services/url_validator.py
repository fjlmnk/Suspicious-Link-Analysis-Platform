import re
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, List


class URLValidator:
    """Service for validating and analyzing URLs for suspicious characteristics."""

    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "bl.ink", "lnkd.in",
        "rb.gy", "shorturl.at", "tiny.cc",
    }

    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".club", ".work", ".click", ".loan",
        ".win", ".gq", ".ml", ".cf", ".tk", ".ga",
    }

    MISLEADING_KEYWORDS = {
        "login", "secure", "bank", "account", "verify", "update",
        "confirm", "signin", "password", "credential", "wallet",
        "paypal", "apple", "microsoft", "google", "amazon",
    }

    @staticmethod
    def validate(url: str) -> Tuple[bool, str, List[str]]:
        """
        Validate a URL.

        Returns:
            (is_valid, normalized_url, warnings)
            ``warnings`` is a list of human-readable strings about suspicious
            characteristics found in the URL.
        """
        warnings: List[str] = []

        # 1. Check not empty
        if not url or not url.strip():
            return False, "", ["URL is empty"]

        url = url.strip()

        # 2. Check for explicit unsupported protocols (ftp://, javascript:, data:, etc.)
        protocol_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*):", url)
        if protocol_match:
            scheme = protocol_match.group(1).lower()
            if scheme not in ("http", "https"):
                return False, url, [f"Invalid scheme '{scheme}'. Only http and https are allowed."]
        else:
            # Scheme missing: check for whitespace or missing dot
            if " " in url or "." not in url:
                return False, url, ["Malformed URL: not a valid web address"]
            url = "https://" + url

        # 3. Parse
        try:
            parsed = urlparse(url)
        except Exception:
            return False, url, ["URL could not be parsed"]

        # 4. Validate scheme
        if parsed.scheme not in ("http", "https"):
            return False, url, [f"Invalid scheme '{parsed.scheme}'. Only http and https are allowed."]

        # 5. Validate hostname
        hostname = parsed.hostname
        if not hostname or " " in hostname or "." not in hostname:
            return False, url, ["URL has no valid hostname"]
        if not hostname:
            return False, url, ["URL has no hostname"]

        # 6 & 7. Check IP-based URLs and private/reserved ranges
        if URLValidator.is_private_ip(hostname):
            return False, url, [
                "URL points to a private or reserved IP address. "
                "This is blocked for SSRF protection."
            ]

        # Check if it's an IP at all (public)
        try:
            ipaddress.ip_address(hostname)
            warnings.append(
                "URL uses a raw IP address instead of a domain name, "
                "which is common in phishing links."
            )
        except ValueError:
            pass  # Not an IP – normal domain

        # 8. Suspicious TLDs
        for tld in URLValidator.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                warnings.append(
                    f"Domain uses suspicious TLD '{tld}' which is frequently "
                    "associated with phishing and spam."
                )
                break

        # 9. URL shorteners
        base_domain = hostname.lower()
        if base_domain in URLValidator.SHORTENER_DOMAINS:
            warnings.append(
                f"URL uses a known URL shortener ({base_domain}). "
                "The actual destination is hidden."
            )

        # 10. Excessive subdomains
        parts = hostname.split(".")
        if len(parts) > 4:
            warnings.append(
                f"URL has an unusually high number of subdomains ({len(parts)}), "
                "which is a common phishing technique."
            )

        # 11. Misleading domain keywords
        lower_hostname = hostname.lower()
        found_keywords = [
            kw for kw in URLValidator.MISLEADING_KEYWORDS
            if kw in lower_hostname
        ]
        if found_keywords:
            warnings.append(
                f"Domain contains potentially misleading keywords: "
                f"{', '.join(found_keywords)}. This may indicate a phishing attempt."
            )

        # 12. URL length
        if len(url) > 500:
            warnings.append(
                f"URL is unusually long ({len(url)} characters), "
                "which can be used to obscure the actual destination."
            )

        # Additional suspicious pattern checks
        pattern_warnings = URLValidator.check_suspicious_patterns(url, parsed)
        warnings.extend(pattern_warnings)

        # 13. Return normalized URL and warnings
        normalized = parsed.geturl()
        return True, normalized, warnings

    @staticmethod
    def is_private_ip(hostname: str) -> bool:
        """Check if hostname resolves to a private/reserved IP range."""
        # Direct check for localhost names
        if hostname.lower() in ("localhost", "localhost.localdomain"):
            return True

        try:
            addr = ipaddress.ip_address(hostname)
        except ValueError:
            # Not an IP literal – could be a domain.
            # Check for common local domain patterns.
            if hostname.lower().endswith(".local"):
                return True
            return False

        # 127.0.0.0/8 – loopback
        if addr.is_loopback:
            return True
        # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if addr.is_private:
            return True
        # 169.254.0.0/16 – link-local
        if addr.is_link_local:
            return True
        # reserved, unspecified, multicast
        if addr.is_reserved or addr.is_unspecified or addr.is_multicast:
            return True
        # IPv6 mapped IPv4 private
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            mapped = addr.ipv4_mapped
            if mapped.is_private or mapped.is_loopback or mapped.is_link_local:
                return True

        return False

    @staticmethod
    def check_suspicious_patterns(url: str, parsed) -> List[str]:
        """Detect suspicious URL patterns that might indicate phishing."""
        warnings: List[str] = []

        # "@" in URL (can be used to mislead – user info part)
        if "@" in (parsed.netloc or ""):
            warnings.append(
                "URL contains '@' in the netloc, which can be used to "
                "disguise the real destination (e.g. http://trusted.com@evil.com)."
            )

        # Excessive dots in hostname
        hostname = parsed.hostname or ""
        dot_count = hostname.count(".")
        if dot_count > 5:
            warnings.append(
                f"Hostname has an excessive number of dots ({dot_count}), "
                "which may indicate a deceptive subdomain structure."
            )

        # Encoded characters / percent-encoding obfuscation in hostname
        if "%" in hostname:
            warnings.append(
                "Hostname contains percent-encoded characters, which may "
                "indicate an attempt to obfuscate the real domain."
            )

        # Homograph-style patterns: digits that look like letters (e.g. 0 for o)
        homograph_pattern = re.compile(r"[a-z]+[0-9]+[a-z]+|[0-9]+[a-z]+[0-9]+", re.IGNORECASE)
        if hostname and homograph_pattern.search(hostname.split(".")[0]):
            warnings.append(
                "Domain name mixes letters and digits in a pattern that could "
                "indicate a homograph or typosquatting attack."
            )

        # Double scheme (e.g. http://http://...)
        path = parsed.path or ""
        if re.search(r"https?://", path, re.IGNORECASE):
            warnings.append(
                "URL appears to contain a second URL in its path, which may "
                "indicate an open redirect or phishing attempt."
            )

        # Data URI or javascript scheme hidden in URL
        if re.search(r"(data|javascript):", url, re.IGNORECASE):
            warnings.append(
                "URL contains a potentially dangerous protocol reference "
                "(data: or javascript:)."
            )

        return warnings
