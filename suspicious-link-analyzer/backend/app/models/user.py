from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, List

from sqlalchemy import DateTime, Enum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import UserRole

if TYPE_CHECKING:
    from app.models.scan_request import ScanRequest


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(256), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.REGULAR, nullable=False)
    company_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    department: Mapped[str | None] = mapped_column(String(256), nullable=True)

    scan_requests: Mapped[List["ScanRequest"]] = relationship(
        "ScanRequest",
        back_populates="user",
        lazy="selectin",
    )
