from pydantic import BaseModel
from typing import Generic, TypeVar, List

T = TypeVar('T')


class PageResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int


class HealthResponse(BaseModel):
    status: str
    database: str
    redis: str
    elasticsearch: str
