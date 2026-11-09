from fastapi import Depends, HTTPException, Header, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime

from app.database import get_db
from app.models.user import User
from app.models.enums import UserRole

async def get_or_create_user(
    x_session_id: str = Header("default-session", alias="X-Session-Id"),
    db: AsyncSession = Depends(get_db)
) -> User:
    stmt = select(User).where(User.session_id == x_session_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        user = User(
            session_id=x_session_id,
            role=UserRole.REGULAR,
            created_at=datetime.utcnow()
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    return user

async def require_employee(
    user: User = Depends(get_or_create_user)
) -> User:
    if user.role != UserRole.COMPANY_EMPLOYEE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Company Employee access required for this action."
        )
    return user
