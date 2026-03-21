from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db

router = APIRouter()


@router.get("/jobs")
async def list_jobs(db: Session = Depends(get_db)):
    return {"jobs": []}


@router.get("/jobs/{job_id}")
async def get_job(job_id: int):
    return {"job_id": job_id}


@router.get("/jobs/{job_id}/logs")
async def get_job_logs(job_id: int):
    return {"logs": []}
