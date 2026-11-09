from fastapi import APIRouter, Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime

from app.database import get_db
from app.models.user import User
from app.models.enums import UserRole
from app.schemas.user import UserCreate, UserResponse
from app.api.deps import get_or_create_user

router = APIRouter()

@router.post("/auth/session", response_model=UserResponse)
async def update_or_create_session(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.session_id == payload.session_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        user = User(
            session_id=payload.session_id,
            role=payload.role or UserRole.REGULAR,
            company_name=payload.company_name,
            department=payload.department,
            created_at=datetime.utcnow()
        )
        db.add(user)
    else:
        if payload.role is not None:
            user.role = payload.role
        if payload.company_name is not None:
            user.company_name = payload.company_name
        if payload.department is not None:
            user.department = payload.department

    await db.commit()
    await db.refresh(user)
    return user

@router.get("/users/me", response_model=UserResponse)
async def get_current_user_profile(
    user: User = Depends(get_or_create_user)
):
    return user
