from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class FindingBase(BaseModel):
    title: str
    severity: str
    cvss_score: Optional[float] = None
    status: str = "OPEN"


class FindingCreate(FindingBase):
    asset_id: int


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None


class Finding(FindingBase):
    id: int
    asset_id: int
    created_at: datetime

    class Config:
        from_attributes = True
