from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from app.models.enums import ThreatLevel


class ProviderVerdictResponse(BaseModel):
    id: int
    provider_name: str
    is_malicious: bool
    detection_count: int
    category: Optional[str] = None
    checked_at: datetime
    provider_status: str

    model_config = {"from_attributes": True}


class ThreatReportResponse(BaseModel):
    id: int
    request_id: int
    threat_level: ThreatLevel
    risk_score: float
    explanation: str
    generated_at: datetime
    provider_verdicts: List[ProviderVerdictResponse] = []

    model_config = {"from_attributes": True}


class SendToSecurityTeamRequest(BaseModel):
    email: Optional[str] = None


class SendToSecurityTeamResponse(BaseModel):
    success: bool
    message: str
