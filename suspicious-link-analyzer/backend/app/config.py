from __future__ import annotations

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    DATABASE_URL: str = "sqlite+aiosqlite:///./suspicious_links.db"
    VIRUSTOTAL_API_KEY: str = ""
    SAFEBROWSING_API_KEY: str = ""
    SECRET_KEY: str = "c2VjdXJlLXJhbmRvbS1rZXktZm9yLXN1c3BpY2lvdXMtbGluay1hbmFseXplcg=="
    VIRUSTOTAL_ENDPOINT: str = "https://www.virustotal.com/api/v3"
    SAFEBROWSING_ENDPOINT: str = "https://safebrowsing.googleapis.com/v4"
    MAX_SCANS_PER_HOUR: int = 20
    SCAN_TIMEOUT_SEC: int = 30
    VIRUSTOTAL_DAILY_LIMIT: int = 500
    SAFEBROWSING_DAILY_LIMIT: int = 10000
    DEMO_MODE_ENABLED: bool = True
    SECURITY_TEAM_EMAIL: str = "security@company.com"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
