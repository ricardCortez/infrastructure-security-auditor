from fastapi import APIRouter
from ..schemas.common import HealthResponse

router = APIRouter()


@router.get("/health/ready", response_model=HealthResponse)
async def health_ready() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        database="connected",
        redis="connected",
        elasticsearch="connected",
    )


@router.get("/health/live")
async def health_live() -> dict:
    return {"status": "ok"}
