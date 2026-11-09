from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from app.models.enums import ScanStatus
from app.schemas.report import ThreatReportResponse


class ScanCreate(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def url_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("URL must not be blank")
        return v.strip()


class ScanResponse(BaseModel):
    id: int
    url: str
    submitted_at: datetime
    status: ScanStatus
    is_demo: bool
    user_id: int
    threat_report: Optional[ThreatReportResponse] = None

    model_config = {"from_attributes": True}


class ScanHistoryResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    page_size: int
