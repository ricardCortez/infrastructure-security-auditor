from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from ..database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, unique=True, index=True)
    ip_address = Column(String, index=True)
    asset_type = Column(String)
    criticality = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
