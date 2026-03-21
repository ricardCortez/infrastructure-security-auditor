from sqlalchemy import Column, Integer, String, Numeric, DateTime, ForeignKey
from sqlalchemy.sql import func
from ..database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    title = Column(String)
    severity = Column(String)
    cvss_score = Column(Numeric(3, 1))
    status = Column(String, default="OPEN")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
