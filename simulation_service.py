from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import HTTPException, Request

from config import EMAIL_PATTERN, PHISHING_TEMPLATES, SIMULATION_STATUS_ORDER
from database import connect_database
from schemas import SimulationLaunchRequest


def is_valid_email_address(email_address: str) -> bool:
    return bool(EMAIL_PATTERN.match(email_address.strip()))


def event_row_to_dict(row: sqlite3.Row, request: Request | None = None) -> dict[str, Any]:
    base_url = str(request.base_url).rstrip("/") if request else ""
    log_id = row["log_id"]
    status = row["status"]
    return {
        "log_id": log_id,
        "campaign_name": row["campaign_name"],
        "target_email": row["target_email"],
        "status": status,
        "timestamp": row["timestamp"],
        "opened_at": row["timestamp"] if SIMULATION_STATUS_ORDER[status] >= SIMULATION_STATUS_ORDER["Opened"] else None,
        "clicked_at": row["timestamp"] if SIMULATION_STATUS_ORDER[status] >= SIMULATION_STATUS_ORDER["Clicked"] else None,
        "compromised_at": row["timestamp"] if status == "Compromised" else None,
        "simulated_link": f"{base_url}/simulated-link/{log_id}" if base_url else f"/simulated-link/{log_id}",
        "tracking_pixel": f"{base_url}/track/open/{log_id}.gif" if base_url else f"/track/open/{log_id}.gif",
    }


def update_event_status(log_id: int, next_status: str) -> None:
    with connect_database() as connection:
        current_event = connection.execute("SELECT status FROM simulation_logs WHERE log_id = ?", (log_id,)).fetchone()
        if current_event is None:
            raise HTTPException(status_code=404, detail="Simulation log not found")

        current_status = current_event["status"]
        if SIMULATION_STATUS_ORDER[next_status] >= SIMULATION_STATUS_ORDER[current_status]:
            connection.execute(
                "UPDATE simulation_logs SET status = ?, timestamp = CURRENT_TIMESTAMP WHERE log_id = ?",
                (next_status, log_id),
            )


def list_recent_events(request: Request, limit: int = 100) -> list[dict[str, Any]]:
    with connect_database() as connection:
        rows = connection.execute("SELECT * FROM simulation_logs ORDER BY log_id DESC LIMIT ?", (limit,)).fetchall()
    return [event_row_to_dict(row, request) for row in rows]


def calculate_dashboard_metrics(request: Request) -> dict[str, Any]:
    with connect_database() as connection:
        total_campaigns = connection.execute("SELECT COUNT(DISTINCT campaign_name) AS total FROM simulation_logs").fetchone()["total"]
        total_events = connection.execute("SELECT COUNT(*) AS total FROM simulation_logs").fetchone()["total"]
        clicked_events = connection.execute(
            "SELECT COUNT(*) AS total FROM simulation_logs WHERE status IN ('Clicked', 'Compromised')"
        ).fetchone()["total"]
        threats_detected = connection.execute("SELECT COUNT(*) AS total FROM detection_logs WHERE risk_score >= 50").fetchone()["total"]
        status_counts = {
            row["status"]: row["total"]
            for row in connection.execute("SELECT status, COUNT(*) AS total FROM simulation_logs GROUP BY status").fetchall()
        }
        recent_rows = connection.execute("SELECT * FROM simulation_logs ORDER BY log_id DESC LIMIT 25").fetchall()

    click_through_rate = round((clicked_events / total_events) * 100, 1) if total_events else 0
    return {
        "total_campaigns": total_campaigns,
        "click_through_rate": click_through_rate,
        "threats_detected": threats_detected,
        "status_counts": status_counts,
        "events": [event_row_to_dict(row, request) for row in recent_rows],
    }


def create_simulation_events(payload: SimulationLaunchRequest, request: Request) -> dict[str, Any]:
    if not payload.safe_test_mode:
        raise HTTPException(status_code=400, detail="Safe Test Mode must remain enabled for local simulations.")
    if payload.template_key not in PHISHING_TEMPLATES:
        raise HTTPException(status_code=400, detail="Unknown phishing template.")

    target_emails = [email.strip().lower() for email in payload.target_emails]
    invalid_targets = [email for email in target_emails if not is_valid_email_address(email)]
    if invalid_targets:
        raise HTTPException(status_code=422, detail=f"Invalid target email: {invalid_targets[0]}")

    created_events: list[dict[str, Any]] = []
    with connect_database() as connection:
        for target_email in dict.fromkeys(target_emails):
            cursor = connection.execute(
                "INSERT INTO simulation_logs (campaign_name, target_email, status) VALUES (?, ?, 'Sent')",
                (payload.campaign_name.strip(), target_email),
            )
            row = connection.execute("SELECT * FROM simulation_logs WHERE log_id = ?", (cursor.lastrowid,)).fetchone()
            created_events.append(event_row_to_dict(row, request))

    return {
        "campaign_name": payload.campaign_name.strip(),
        "template": PHISHING_TEMPLATES[payload.template_key],
        "created": created_events,
    }


def training_landing_page(log_id: int) -> str:
    return f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Lurex Training Moment</title>
        <style>
          :root {{ color-scheme: dark; font-family: 'Segoe UI', system-ui, sans-serif; }}
          body {{ min-height: 100vh; margin: 0; display: grid; place-items: center; background: #0f172a; color: #f8fafc; }}
          main {{ width: min(720px, calc(100vw - 32px)); border: 1px solid #334155; border-radius: 8px; padding: 32px; background: #111827; box-shadow: 0 24px 80px rgba(0,0,0,.35); }}
          .tag {{ display: inline-flex; padding: 6px 10px; border: 1px solid #facc15; color: #facc15; border-radius: 999px; font-size: 12px; letter-spacing: 0; text-transform: uppercase; }}
          h1 {{ font-size: clamp(32px, 5vw, 56px); line-height: 1; margin: 18px 0; }}
          p {{ color: #cbd5e1; font-size: 18px; line-height: 1.6; }}
          a {{ color: #38bdf8; }}
        </style>
      </head>
      <body>
        <main>
          <span class="tag">Safe Test Mode</span>
          <h1>This was a test. You clicked on a simulated link.</h1>
          <p>No credentials were collected and no external mail system was used. Log #{log_id} has been updated locally so the evaluator can review the training event.</p>
          <p><a href="/">Return to Lurex Portal</a></p>
        </main>
      </body>
    </html>
    """
