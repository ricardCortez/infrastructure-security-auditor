"""Local development runner using SQLite (no Docker required)."""
import os

# Override database URL before any imports
os.environ["DATABASE_URL"] = "sqlite:///./psi_local.db"
os.environ["API_DEBUG"] = "true"
os.environ["API_SECRET_KEY"] = "local-dev-secret-key"

from app.database import engine, Base  # noqa: E402
import app.models.user  # noqa: E402, F401
import app.models.asset  # noqa: E402, F401
import app.models.finding  # noqa: E402, F401
import app.models.scan_job  # noqa: E402, F401

print("Creating database tables...")
Base.metadata.create_all(bind=engine)
print("OK - Tables created: users, assets, findings, scan_jobs")

import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
