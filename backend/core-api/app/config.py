from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    database_url: str = "sqlite:///./psi_local.db"
    redis_url: str = "redis://redis:6379"
    elasticsearch_host: str = "elasticsearch"
    elasticsearch_port: int = 9200
    api_secret_key: str = "dev-secret-key-change-in-prod"
    api_debug: bool = True

    class Config:
        env_file = ".env"


settings = Settings()
