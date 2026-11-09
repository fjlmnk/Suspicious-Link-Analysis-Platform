from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

from app.models.enums import ScanStatus
from app.schemas.report import ThreatReportResponse


class DemoScenario(BaseModel):
    id: str
    name: str
    url: str
    description: str
    expected_threat_level: str


class DemoScanCreate(BaseModel):
    scenario_id: str


class DemoScanResponse(BaseModel):
    id: int
    url: str
    submitted_at: datetime
    status: ScanStatus
    is_demo: bool
    user_id: int
    threat_report: Optional[ThreatReportResponse] = None
    demo_notice: str = "This is a simulated demo result and does not reflect real threat intelligence data."

    model_config = {"from_attributes": True}
