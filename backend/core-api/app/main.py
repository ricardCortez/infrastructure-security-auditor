from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .routers import users, assets, findings, reports, jobs, health


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting up...")
    yield
    print("Shutting down...")


app = FastAPI(
    title="PSI - Plataforma de Seguridad Integrada",
    description="Enterprise security platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(users.router, prefix="/api/v1", tags=["users"])
app.include_router(assets.router, prefix="/api/v1", tags=["assets"])
app.include_router(findings.router, prefix="/api/v1", tags=["findings"])
app.include_router(reports.router, prefix="/api/v1", tags=["reports"])
app.include_router(jobs.router, prefix="/api/v1", tags=["jobs"])
