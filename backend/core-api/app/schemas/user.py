from pydantic import BaseModel
from typing import Optional
from datetime import datetime

EmailStr = str  # Plain str in dev to avoid strict DNS validation


class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "analyst"


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class User(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True
