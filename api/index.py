"""Vercel entrypoint for the Nexus FastAPI application."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.main import app


@app.get("/", include_in_schema=False)
async def root():
    return {"service": "Nexus Campus API", "status": "ok", "health": "/health/live", "docs": "/docs"}
