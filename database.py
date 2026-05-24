from __future__ import annotations

import sqlite3

from config import DATABASE_PATH


def connect_database() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with connect_database() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS simulation_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_name TEXT NOT NULL,
                target_email TEXT NOT NULL,
                status TEXT CHECK(status IN ('Sent', 'Opened', 'Clicked', 'Compromised')),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_logs (
                detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
                input_type TEXT CHECK(input_type IN ('email', 'url')),
                risk_score INTEGER NOT NULL,
                summary TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        seed_demo_data(connection)


def seed_demo_data(connection: sqlite3.Connection) -> None:
    simulation_count = connection.execute("SELECT COUNT(*) AS total FROM simulation_logs").fetchone()["total"]
    if simulation_count == 0:
        connection.executemany(
            "INSERT INTO simulation_logs (campaign_name, target_email, status) VALUES (?, ?, ?)",
            [
                ("Quarterly Awareness Drill", "maya@northwind.example", "Sent"),
                ("Quarterly Awareness Drill", "dev@northwind.example", "Opened"),
                ("Payroll Resilience Test", "finance@northwind.example", "Clicked"),
                ("Credential Hygiene Drill", "ops@northwind.example", "Compromised"),
                ("Credential Hygiene Drill", "ana@northwind.example", "Opened"),
            ],
        )

    detection_count = connection.execute("SELECT COUNT(*) AS total FROM detection_logs").fetchone()["total"]
    if detection_count == 0:
        connection.executemany(
            "INSERT INTO detection_logs (input_type, risk_score, summary) VALUES (?, ?, ?)",
            [
                ("email", 72, "Seeded demonstration: urgency, reply-to mismatch, suspicious URL."),
                ("url", 18, "Seeded demonstration: informational low-risk URL scan."),
            ],
        )
