# PhishShield Portal

Interactive local cybersecurity training portal with two workflows:

- Simulation Studio creates safe, localhost-only phishing simulations and logs target status in SQLite.
- Threat Analytics Engine runs header, lexical, and URL heuristics against pasted email content or URLs.

## Project Structure

```text
phishshield_portal/
  main.py                  FastAPI routes and app startup
  config.py                Shared paths, templates, regex rules, and constants
  database.py              SQLite connection, schema creation, and demo seed data
  detection_engine.py      Header, lexical, URL, and typosquatting heuristics
  simulation_service.py    Campaign creation, status tracking, and landing page HTML
  schemas.py               Request validation models
  static/
    index.html             Portal layout
    portal.css             Visual system and responsive layout
    portal.js              Browser interactions and API calls
  data/
    .gitkeep               Runtime SQLite database folder
```

## Run

```powershell
cd "d:\shivam study material\Websites\task 4"
python -m uvicorn phishshield_portal.main:app --host 127.0.0.1 --port 8000
```

Then open http://127.0.0.1:8000.

## Safety Model

The simulator does not send external email. Every generated lure URL routes to `/simulated-link/{log_id}` on the local FastAPI server, and tracking pixels route to `/track/open/{log_id}.gif` on the same host.

## Verification Matrix

| Objective | Implementation | UI Surface |
| --- | --- | --- |
| Simulate attacks | `/api/simulations` writes safe campaign events to `simulation_logs` | Simulation Studio |
| Test awareness | Local tracking pixel and dummy redirect status updates | Live Event Feed |
| Email filter mechanisms | Header validator, lexical scanner, URL scanner | Risk Gauge and Breakdown |
| Fake website detection | URL structure checks and Levenshtein look-alike matching | Analyze URL tab |

SQLite data is created at `phishshield_portal/data/phishshield.db`.
