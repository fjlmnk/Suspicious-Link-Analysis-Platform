from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.demo import DemoScenario, DemoScanCreate, DemoScanResponse
from app.api.deps import get_or_create_user
from app.services.demo_service import DemoService

router = APIRouter()

@router.get("/demo/scenarios", response_model=List[DemoScenario])
async def list_demo_scenarios():
    return DemoService.get_scenarios()

@router.post("/demo/scans", response_model=DemoScanResponse, status_code=status.HTTP_201_CREATED)
async def run_demo_scan(
    payload: DemoScanCreate,
    user: User = Depends(get_or_create_user),
    db: AsyncSession = Depends(get_db),
):
    scan_req = await DemoService.run_scenario(payload.scenario_id, user.id, db)
    return scan_req
