import asyncio
import base64
import json

import httpx

from .base import ThreatDataProvider, ProviderVerdictResult


class VirusTotalProvider(ThreatDataProvider):
    """VirusTotal v3 API integration."""

    def __init__(
        self,
        api_key: str,
        api_endpoint: str,
        daily_request_limit: int = 500,
    ):
        super().__init__("VirusTotal", api_key, daily_request_limit)
        self.api_endpoint = api_endpoint

    async def check_url(self, url: str) -> ProviderVerdictResult:
        """Check URL against VirusTotal API v3."""
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
            # URL ID for VT is base64url of URL without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

            headers = {"x-apikey": self.api_key}

            async with httpx.AsyncClient(timeout=15.0) as client:
                # Try to get existing analysis
                response = await client.get(
                    f"{self.api_endpoint}/urls/{url_id}",
                    headers=headers,
                )

                if response.status_code == 404:
                    # Submit URL for analysis
                    submit_response = await client.post(
                        f"{self.api_endpoint}/urls",
                        headers=headers,
                        data={"url": url},
                    )

                    if submit_response.status_code in (200, 201):
                        # Wait briefly then fetch results
                        await asyncio.sleep(2)
                        response = await client.get(
                            f"{self.api_endpoint}/urls/{url_id}",
                            headers=headers,
                        )
                    else:
                        return ProviderVerdictResult(
                            provider_name=self.name,
                            is_malicious=False,
                            detection_count=0,
                            category=f"Submit failed: HTTP {submit_response.status_code}",
                            provider_status="ERROR",
                        )

                if response.status_code == 200:
                    data = response.json()
                    return self._parse_response(data)
                elif response.status_code == 401:
                    return ProviderVerdictResult(
                        provider_name=self.name,
                        is_malicious=False,
                        detection_count=0,
                        category="Invalid API key",
                        provider_status="AUTH_ERROR",
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
        """Parse VirusTotal API response and build a verdict."""
        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            total = malicious + suspicious + harmless + undetected
            detection_count = malicious + suspicious

            # Determine category
            categories = []
            if malicious > 0:
                categories.append("malicious")
            if suspicious > 0:
                categories.append("suspicious")

            # Consider malicious if any engine flags it
            is_malicious = malicious > 0

            category_str = ", ".join(categories) if categories else "clean"

            # Add detection ratio to category
            if total > 0:
                category_str += f" ({detection_count}/{total} engines)"

            raw = json.dumps(
                {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total": total,
                }
            )

            return ProviderVerdictResult(
                provider_name=self.name,
                is_malicious=is_malicious,
                detection_count=detection_count,
                category=category_str,
                provider_status="SUCCESS",
                raw_response=raw,
            )
        except Exception as e:
            return ProviderVerdictResult(
                provider_name=self.name,
                is_malicious=False,
                detection_count=0,
                category=f"Parse error: {str(e)[:100]}",
                provider_status="ERROR",
            )
