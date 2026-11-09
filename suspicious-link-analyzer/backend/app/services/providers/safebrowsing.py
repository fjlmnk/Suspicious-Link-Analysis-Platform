import json

import httpx

from .base import ThreatDataProvider, ProviderVerdictResult


class SafeBrowsingProvider(ThreatDataProvider):
    """Google Safe Browsing Lookup API v4 integration."""

    THREAT_TYPES = [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    ]

    PLATFORM_TYPES = ["ANY_PLATFORM"]
    THREAT_ENTRY_TYPES = ["URL"]

    def __init__(
        self,
        api_key: str,
        api_endpoint: str,
        daily_request_limit: int = 10000,
    ):
        super().__init__("Google Safe Browsing", api_key, daily_request_limit)
        self.api_endpoint = api_endpoint

    async def check_url(self, url: str) -> ProviderVerdictResult:
        """Check URL against Google Safe Browsing Lookup API v4."""
        if not self.api_key:
            return ProviderVerdictResult(
                provider_name=self.name,
                is_malicious=False,
                detection_count=0,
                category="API key not configured",
                provider_status="UNAVAILABLE",
            )

        if self.is_limit_reached():
            return ProviderVerdictResult(
                provider_name=self.name,
                is_malicious=False,
                detection_count=0,
                category="Daily limit reached",
                provider_status="RATE_LIMITED",
            )

        self._increment_counter()

        try:
            request_body = {
                "client": {
                    "clientId": "suspicious-link-analyzer",
                    "clientVersion": "1.0.0",
                },
                "threatInfo": {
                    "threatTypes": self.THREAT_TYPES,
                    "platformTypes": self.PLATFORM_TYPES,
                    "threatEntryTypes": self.THREAT_ENTRY_TYPES,
                    "threatEntries": [{"url": url}],
                },
            }

            api_url = f"{self.api_endpoint}/threatMatches:find?key={self.api_key}"

            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(api_url, json=request_body)

            if response.status_code == 200:
                return self._parse_response(response.json())
            elif response.status_code == 400:
                return ProviderVerdictResult(
                    provider_name=self.name,
                    is_malicious=False,
                    detection_count=0,
                    category="Bad request",
                    provider_status="ERROR",
                    raw_response=response.text[:500],
                )
            elif response.status_code == 403:
                return ProviderVerdictResult(
                    provider_name=self.name,
                    is_malicious=False,
                    detection_count=0,
                    category="Forbidden – invalid API key or quota exceeded",
                    provider_status="AUTH_ERROR",
                    raw_response=response.text[:500],
                )
            elif response.status_code == 429:
                return ProviderVerdictResult(
                    provider_name=self.name,
                    is_malicious=False,
                    detection_count=0,
                    category="Rate limit exceeded",
                    provider_status="RATE_LIMITED",
                )
            else:
                return ProviderVerdictResult(
                    provider_name=self.name,
                    is_malicious=False,
                    detection_count=0,
                    category=f"HTTP {response.status_code}",
                    provider_status="ERROR",
                    raw_response=response.text[:500],
                )

        except httpx.TimeoutException:
            return ProviderVerdictResult(
                provider_name=self.name,
                is_malicious=False,
                detection_count=0,
                category="Request timeout",
                provider_status="TIMEOUT",
            )
        except Exception as e:
            return ProviderVerdictResult(
                provider_name=self.name,
                is_malicious=False,
                detection_count=0,
                category=f"Error: {str(e)[:100]}",
                provider_status="ERROR",
            )

    def _parse_response(self, data: dict) -> ProviderVerdictResult:
        """Parse the Safe Browsing API response."""
        try:
            matches = data.get("matches", [])

            if not matches:
                # No threats found – URL is clean
                return ProviderVerdictResult(
                    provider_name=self.name,
                    is_malicious=False,
                    detection_count=0,
                    category="clean",
                    provider_status="SUCCESS",
                    raw_response=json.dumps(data),
                )

            # URL is flagged
            threat_types_found = list(
                {m.get("threatType", "UNKNOWN") for m in matches}
            )
            detection_count = len(matches)
            category_str = ", ".join(threat_types_found)

            return ProviderVerdictResult(
                provider_name=self.name,
                is_malicious=True,
                detection_count=detection_count,
                category=category_str,
                provider_status="SUCCESS",
                raw_response=json.dumps(data),
            )
        except Exception as e:
            return ProviderVerdictResult(
                provider_name=self.name,
                is_malicious=False,
                detection_count=0,
                category=f"Parse error: {str(e)[:100]}",
                provider_status="ERROR",
            )
