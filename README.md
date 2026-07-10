# PrivacyGuard

A personal cyber-safety toolkit: it scans URLs for tracking and phishing risk
and gives you an interactive dashboard to explore your browsing privacy.

## Features

- **URL Risk & Phishing Scanner** — combines a known-tracker domain list
  (DuckDuckGo Tracker Radar), query-parameter analysis (credential/token leaks,
  UTM/click-ID tracking params), and phishing heuristics (typosquatting,
  homoglyphs, suspicious TLDs, IP-literal URLs) into a single 0–10 risk score
  with a Random Forest confidence estimate.
- **Web Dashboard** — scan URLs, review history, see risk distribution and top
  trackers, and trigger a full browser-history scan, all from one page.

## Architecture

```
src/privacyguard/
  core/        risk_engine, url_utils, parameter_detector, phishing_detector, tracker_loader
  features/    ML feature vector builder
  ml/          train.py / predict.py (Random Forest, auto-trains on first run)
  db/          SQLite (default) or PostgreSQL, schema + CRUD
  browser/     multi-browser history extraction
  api/         FastAPI app, routes, schemas
  static/      dashboard (HTML/CSS/JS, Chart.js)
  main.py      CLI entry point
```

The ML model isn't trained from a labeled ground-truth dataset — there isn't
one lying around for "is this URL risky." Instead `ml/train.py` generates a
synthetic corpus of clean, tracker, credential-leak, and phishing-style URLs,
labels each with `core.risk_engine`'s deterministic rules, and trains a Random
Forest to reproduce that mapping from the feature vector. This turns a fast
rule engine into something that also yields a calibrated confidence score. If
no model file exists yet, `ml/predict.py` trains one on the fly — no setup
step required to get going.

## Installation

```bash
python -m venv venv
venv\Scripts\activate            # Windows
pip install -e ".[dev]"
copy .env.example .env           # then edit as needed
```

SQLite is the default database — no extra configuration needed. To use
PostgreSQL instead, install the extra and set `DB_TYPE=postgres` in `.env`:

```bash
pip install -e ".[postgres]"
```

## Usage

```bash
privacyguard                     # launch dashboard + API at http://127.0.0.1:8000
privacyguard scan <url>          # scan a single URL from the CLI
privacyguard history             # scan local browser history (Chrome/Edge/Firefox/Brave)
privacyguard train               # retrain the ML model
```

Or run the API directly with uvicorn:

```bash
uvicorn privacyguard.api.app:app --reload
```

Interactive API docs are available at `/docs` once the server is running.

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Web dashboard |
| `GET` | `/api/health` | Health check + model/tracker status |
| `POST` | `/api/scan/url` | Scan a single URL |
| `POST` | `/api/scan/batch` | Scan multiple URLs |
| `POST` | `/api/scan/browser` | Scan local browser history |
| `GET` | `/api/history` | Paginated scan history (supports `risk_label` filter) |
| `GET` | `/api/stats` | Dashboard stats |
| `GET` | `/api/stats/trackers` | Top tracker companies |

## Testing

```bash
pytest tests/ -v --cov=src/privacyguard
```
