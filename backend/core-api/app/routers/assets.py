from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models.asset import Asset as AssetModel
from ..schemas.asset import Asset, AssetCreate, AssetUpdate

router = APIRouter()


@router.get("/assets", response_model=list[Asset])
async def list_assets(db: Session = Depends(get_db)):
    return db.query(AssetModel).all()


@router.post("/assets", response_model=Asset)
async def create_asset(asset: AssetCreate, db: Session = Depends(get_db)):
    db_asset = AssetModel(**asset.model_dump())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset


@router.get("/assets/{asset_id}", response_model=Asset)
async def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.put("/assets/{asset_id}", response_model=Asset)
async def update_asset(asset_id: int, asset: AssetUpdate, db: Session = Depends(get_db)):
    db_asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    update_data = asset.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_asset, field, value)
    db.commit()
    db.refresh(db_asset)
    return db_asset


@router.delete("/assets/{asset_id}")
async def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    db_asset = db.query(AssetModel).filter(AssetModel.id == asset_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(db_asset)
    db.commit()
    return {"deleted": True}
