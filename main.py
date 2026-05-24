from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from .config import DATABASE_PATH, PHISHING_TEMPLATES, STATIC_DIR, TRANSPARENT_PIXEL_GIF
from .database import initialize_database
from .detection_engine import analyze_threat_content
from .schemas import SimulationLaunchRequest, SimulationStatusUpdate, ThreatAnalysisRequest
from .simulation_service import (
    calculate_dashboard_metrics,
    create_simulation_events,
    list_recent_events,
    training_landing_page,
    update_event_status,
)


app = FastAPI(title="Lurex Portal", version="1.0.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
def startup() -> None:
    initialize_database()


@app.get("/", response_class=HTMLResponse)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/portal.css")
def portal_css() -> FileResponse:
    return FileResponse(STATIC_DIR / "portal.css")


@app.get("/portal.js")
def portal_js() -> FileResponse:
    return FileResponse(STATIC_DIR / "portal.js")


@app.get("/training.html", response_class=HTMLResponse)
def static_training_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "training.html")


@app.get("/api/templates")
def templates() -> dict[str, Any]:
    return {"templates": [{"key": key, **value} for key, value in PHISHING_TEMPLATES.items()]}


@app.get("/api/metrics")
def metrics(request: Request) -> dict[str, Any]:
    return calculate_dashboard_metrics(request)


@app.get("/api/events")
def events(request: Request) -> dict[str, Any]:
    return {"events": list_recent_events(request)}


@app.post("/api/simulations")
def launch_simulation(payload: SimulationLaunchRequest, request: Request) -> dict[str, Any]:
    return create_simulation_events(payload, request)


@app.post("/api/events/{log_id}/status")
def set_event_status(log_id: int, payload: SimulationStatusUpdate) -> dict[str, Any]:
    update_event_status(log_id, payload.status)
    return {"ok": True, "log_id": log_id, "status": payload.status}


@app.get("/track/open/{log_id}.gif")
def tracking_pixel(log_id: int) -> Response:
    update_event_status(log_id, "Opened")
    return Response(content=TRANSPARENT_PIXEL_GIF, media_type="image/gif", headers={"Cache-Control": "no-store"})


@app.get("/simulated-link/{log_id}", response_class=HTMLResponse)
def simulated_link(log_id: int) -> HTMLResponse:
    update_event_status(log_id, "Clicked")
    return HTMLResponse(training_landing_page(log_id))


@app.post("/api/analyze/email")
def analyze_email(payload: ThreatAnalysisRequest) -> dict[str, Any]:
    return analyze_threat_content(payload.content, "email")


@app.post("/api/analyze/url")
def analyze_url(payload: ThreatAnalysisRequest) -> dict[str, Any]:
    return analyze_threat_content(payload.content, "url")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "database": str(DATABASE_PATH)}
