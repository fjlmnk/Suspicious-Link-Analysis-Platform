import json
import logging
from datetime import datetime
from typing import Optional

import httpx

from .base import ThreatDataProvider, ProviderVerdictResult

logger = logging.getLogger(__name__)


class URLhausProvider(ThreatDataProvider):
    """URLhaus (abuse.ch) API integration for malware URL threat intelligence."""

    def __init__(
        self,
        api_key: str,
        api_endpoint: str = "https://urlhaus-api.abuse.ch/v1",
        daily_request_limit: int = 5000,
    ):
        super().__init__("URLhaus (abuse.ch)", api_key, daily_request_limit)
        self.api_endpoint = api_endpoint.rstrip("/")

    async def check_url(self, url: str) -> ProviderVerdictResult:
        """
        Check URL against URLhaus API.

        URLhaus tracks malicious URLs distributing malware and ransomware.
        POST to /url/ with form data `url=<url>` and optional Auth-Key header.
        """
        if self.is_limit_reached():
            return ProviderVerdictResult(
                provider_name=self.name,
                is_malicious=False,
                detection_count=0,
                category="Daily request limit reached",
                provider_status="RATE_LIMITED",
            )

        self._increment_counter()

        headers = {}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        data = {"url": url}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    f"{self.api_endpoint}/url/",
                    data=data,
                    headers=headers,
                )

                if response.status_code == 200:
                    res_json = response.json()
                    query_status = res_json.get("query_status", "")

                    if query_status == "ok":
                        # URL found in malware database
                        threat = res_json.get("threat", "malware_download")
                        url_status = res_json.get("url_status", "unknown")
                        tags = res_json.get("tags") or []
                        tags_str = f" [tags: {', '.join(tags)}]" if tags else ""
                        payloads = res_json.get("payloads") or []
                        detection_count = max(1, len(payloads))

                        category = f"Malware Distribution: {threat} (status: {url_status}){tags_str}"

                        raw_summary = json.dumps({
                            "id": res_json.get("id"),
                            "urlhaus_reference": res_json.get("urlhaus_reference"),
                            "threat": threat,
                            "url_status": url_status,
                            "tags": tags,
                            "payload_count": len(payloads)
                        })

                        return ProviderVerdictResult(
                            provider_name=self.name,
                            is_malicious=True,
                            detection_count=detection_count,
                            category=category,
                            checked_at=datetime.utcnow(),
                            provider_status="SUCCESS",
                            raw_response=raw_summary,
                        )

                    elif query_status == "no_results":
                        # Clean URL (not flagged as malware)
                        return ProviderVerdictResult(
                            provider_name=self.name,
                            is_malicious=False,
                            detection_count=0,
                            category="Clean (not listed in malware database)",
                            checked_at=datetime.utcnow(),
                            provider_status="SUCCESS",
                        )

                    elif query_status == "invalid_url":
                        return ProviderVerdictResult(
                            provider_name=self.name,
                            is_malicious=False,
                            detection_count=0,
                            category="Invalid URL queried",
                            checked_at=datetime.utcnow(),
                            provider_status="SUCCESS",
                        )

                    else:
                        return ProviderVerdictResult(
                            provider_name=self.name,
                            is_malicious=False,
                            detection_count=0,
                            category=f"Query status: {query_status}",
                            checked_at=datetime.utcnow(),
                            provider_status="SUCCESS",
                        )

                elif response.status_code == 429:
                    return ProviderVerdictResult(
                        provider_name=self.name,
                        is_malicious=False,
                        detection_count=0,
                        category="URLhaus rate limit reached",
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
            logger.error(f"Error checking URLhaus: {e}")
            return ProviderVerdictResult(
                provider_name=self.name,
                is_malicious=False,
                detection_count=0,
                category=f"Service error: {str(e)[:100]}",
                provider_status="ERROR",
            )
