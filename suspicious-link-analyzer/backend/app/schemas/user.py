from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.models.enums import UserRole


class UserCreate(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=256)
    role: Optional[UserRole] = UserRole.REGULAR
    company_name: Optional[str] = None
    department: Optional[str] = None


class UserResponse(BaseModel):
    id: int
    session_id: str
    created_at: datetime
    role: UserRole
    company_name: Optional[str] = None
    department: Optional[str] = None

    model_config = {"from_attributes": True}
