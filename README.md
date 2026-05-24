# Lurex Portal

Lurex is a cybersecurity awareness portal for safe phishing simulations and heuristic email/URL threat analysis, built with FastAPI, SQLite, and a Netlify-friendly frontend.

Interactive local cybersecurity training portal with two workflows:

- Simulation Studio creates safe, localhost-only phishing simulations and logs target status in SQLite.
- Threat Analytics Engine runs header, lexical, and URL heuristics against pasted email content or URLs.

## Project Structure

```text
phishshield_portal/
  netlify.toml             Netlify static deploy configuration
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
    training.html          Static safe-click education page
  data/
    .gitkeep               Runtime SQLite database folder
```

## Run

```powershell
cd "d:\shivam study material\Websites\task 4"
python -m uvicorn phishshield_portal.main:app --host 127.0.0.1 --port 8000
```

Then open http://127.0.0.1:8000.

## Deploy To Netlify

This repository is Netlify-friendly as a static deploy:

1. Push this `phishshield_portal` repository to GitHub.
2. In Netlify, import the GitHub repository.
3. Netlify will read `netlify.toml` and publish the `static` folder.
4. Leave the build command empty.

On Netlify, the browser uses a local demo data store because Netlify static hosting does not run the FastAPI/SQLite backend. The local FastAPI backend still works when you run the app with Uvicorn.

## Safety Model

The simulator does not send external email. Every generated lure URL routes to `/simulated-link/{log_id}` on the local FastAPI server, and tracking pixels route to `/track/open/{log_id}.gif` on the same host.

## Verification Matrix

| Objective | Implementation | UI Surface |
| --- | --- | --- |
| Simulate attacks | `/api/simulations` writes safe campaign events to `simulation_logs` | Simulation Studio |
| Test awareness | Local tracking pixel and dummy redirect status updates | Live Event Feed |
| Email filter mechanisms | Header validator, lexical scanner, URL scanner | Risk Gauge and Breakdown |
| Fake website detection | URL structure checks and Levenshtein look-alike matching | Analyze URL tab |

SQLite data is created at `phishshield_portal/data/lurex.db`.
