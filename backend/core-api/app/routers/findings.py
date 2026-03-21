from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from ..database import get_db
from ..models.finding import Finding as FindingModel
from ..schemas.finding import Finding, FindingCreate, FindingUpdate

router = APIRouter()


@router.get("/findings", response_model=list[Finding])
async def list_findings(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(FindingModel)
    if status:
        query = query.filter(FindingModel.status == status)
    if severity:
        query = query.filter(FindingModel.severity == severity)
    return query.all()


@router.post("/findings", response_model=Finding)
async def create_finding(finding: FindingCreate, db: Session = Depends(get_db)):
    db_finding = FindingModel(**finding.model_dump())
    db.add(db_finding)
    db.commit()
    db.refresh(db_finding)
    return db_finding


@router.get("/findings/{finding_id}", response_model=Finding)
async def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.put("/findings/{finding_id}", response_model=Finding)
async def update_finding(finding_id: int, finding: FindingUpdate, db: Session = Depends(get_db)):
    db_finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not db_finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    update_data = finding.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_finding, field, value)
    db.commit()
    db.refresh(db_finding)
    return db_finding


@router.delete("/findings/{finding_id}")
async def delete_finding(finding_id: int, db: Session = Depends(get_db)):
    db_finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not db_finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.delete(db_finding)
    db.commit()
    return {"deleted": True}
