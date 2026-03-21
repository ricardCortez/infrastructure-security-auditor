from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class AssetBase(BaseModel):
    hostname: str
    ip_address: str
    asset_type: str
    criticality: Optional[str] = "medium"


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    criticality: Optional[str] = None
    asset_type: Optional[str] = None


class Asset(AssetBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True
