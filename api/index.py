"""Vercel entrypoint for the Nexus FastAPI application."""

from app.main import app


@app.get("/", include_in_schema=False)
async def root():
    return {"service": "Nexus Campus API", "status": "ok", "health": "/health/live", "docs": "/docs"}
