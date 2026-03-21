from fastapi import APIRouter, BackgroundTasks
from sqlalchemy.orm import Session

router = APIRouter()


@router.get("/reports")
async def list_reports():
    return {"reports": []}


@router.post("/reports/generate")
async def generate_report(background_tasks: BackgroundTasks):
    background_tasks.add_task(lambda: print("Generating report..."))
    return {"status": "generating"}


@router.get("/reports/{report_id}/download")
async def download_report(report_id: int):
    return {"error": "Not implemented"}
