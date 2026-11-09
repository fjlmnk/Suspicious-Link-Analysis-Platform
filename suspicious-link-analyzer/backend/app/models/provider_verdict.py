from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.threat_report import ThreatReport


class ProviderVerdict(Base):
    __tablename__ = "provider_verdicts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[int] = mapped_column(Integer, ForeignKey("threat_reports.id"), nullable=False, index=True)
    provider_name: Mapped[str] = mapped_column(String(128), nullable=False)
    is_malicious: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    detection_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    category: Mapped[str | None] = mapped_column(String(512), nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    provider_status: Mapped[str] = mapped_column(String(64), default="SUCCESS", nullable=False)
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)

    threat_report: Mapped[Optional["ThreatReport"]] = relationship(
        "ThreatReport",
        back_populates="provider_verdicts",
        lazy="selectin",
    )
