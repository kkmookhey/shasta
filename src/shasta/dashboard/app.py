"""Shasta Compliance Dashboard — FastAPI application."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Shasta Compliance Dashboard")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# Import and include routes
from shasta.dashboard.routes import router  # noqa: E402

app.include_router(router)
