from abc import ABC, abstractmethod
from datetime import datetime, date
from typing import Optional


class ProviderVerdictResult:
    """Result from a threat data provider check."""

    def __init__(
        self,
        provider_name: str,
        is_malicious: bool,
        detection_count: int = 0,
        category: str = "",
        checked_at: Optional[datetime] = None,
        provider_status: str = "SUCCESS",
        raw_response: Optional[str] = None,
    ):
        self.provider_name = provider_name
        self.is_malicious = is_malicious
        self.detection_count = detection_count
        self.category = category
        self.checked_at = checked_at or datetime.utcnow()
        self.provider_status = provider_status
        self.raw_response = raw_response


class ThreatDataProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    def __init__(self, name: str, api_key: str, daily_request_limit: int):
        self.name = name
        self.api_key = api_key
        self.daily_request_limit = daily_request_limit
        self._daily_request_count: int = 0
        self._last_reset_date: Optional[date] = None

    @abstractmethod
    async def check_url(self, url: str) -> ProviderVerdictResult:
        pass

    def is_limit_reached(self) -> bool:
        today = date.today()
        if self._last_reset_date != today:
            self._daily_request_count = 0
            self._last_reset_date = today
        return self._daily_request_count >= self.daily_request_limit

    def _increment_counter(self) -> None:
        today = date.today()
        if self._last_reset_date != today:
            self._daily_request_count = 0
            self._last_reset_date = today
        self._daily_request_count += 1
