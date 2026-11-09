from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import ThreatLevel

if TYPE_CHECKING:
    from app.models.provider_verdict import ProviderVerdict
    from app.models.scan_request import ScanRequest


class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scan_requests.id"), unique=True, nullable=False, index=True
    )
    threat_level: Mapped[ThreatLevel] = mapped_column(Enum(ThreatLevel), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    scan_request: Mapped[Optional["ScanRequest"]] = relationship(
        "ScanRequest",
        back_populates="threat_report",
        lazy="selectin",
    )

    provider_verdicts: Mapped[List["ProviderVerdict"]] = relationship(
        "ProviderVerdict",
        back_populates="threat_report",
        lazy="selectin",
    )
