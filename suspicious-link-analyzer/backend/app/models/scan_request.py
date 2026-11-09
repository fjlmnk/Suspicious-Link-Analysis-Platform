from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import ScanStatus

if TYPE_CHECKING:
    from app.models.threat_report import ThreatReport
    from app.models.user import User


class ScanRequest(Base):
    __tablename__ = "scan_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped["User"] = relationship(
        "User",
        back_populates="scan_requests",
        lazy="selectin",
    )

    threat_report: Mapped[Optional["ThreatReport"]] = relationship(
        "ThreatReport",
        back_populates="scan_request",
        uselist=False,
        lazy="selectin",
    )
