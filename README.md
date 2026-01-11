# Cyber Awareness Response Bot

FastAPI chatbot for Slack, Teams, and web that answers cybersecurity-awareness questions from trusted public authorities and a dynamic training dataset. Live answers come from trusted domains only; every response includes citations.

## Quickstart

1) Create a virtual env and install deps
```bash
python -m venv .venv
```
Linux/macOS
```bash
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```
Windows (PowerShell)
```powershell
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

2) Configure `.env`
```
SLACK_SIGNING_SECRET=...
SLACK_BOT_TOKEN=...
HF_TOKEN=...
HF_MODEL=google/gemma-2-2b-it
MONGO_URI=mongodb://localhost:27017
MONGO_DB_NAME=cyber_training
SESSION_SECRET=change-this-string
ENABLE_LIVE_SEARCH=1
```

3) Run the app
```bash
uvicorn app.main:app --reload --port 8000
```

## What’s inside

- Slack/Teams/web Q&A with moderation, sensitive-data blocking, prompt-injection safeguards, and trusted-domain live search (CISA, NCSC, NIST, OWASP, etc.).
- Cached site search + HTML extraction with strict allow/deny rules; answers always cite the exact pages used.
- Mongo-backed training with level gating and badges; questions stored in `training_datasets`.
- KPI events emitted for logins, module attempts, answers, and Q&A activity.

## Admin and training

- Sign up: `/training/signup`
- Login: `/training/login`
- Admin KPI dashboard: `/admin/kpi` (set `role: "admin"` on the user in Mongo)
- Dataset upload helper: `python scripts/upload_dataset.py dataset.json`

## Trusted sources

Live search is hard-restricted to:
`owasp.org`, `cisa.gov`, `nist.gov`, `ncsc.gov.uk`, `enisa.europa.eu`, `cyber.gov.au`, `pcisecuritystandards.org`, `cert.govt.nz`, `publicsafety.gc.ca`.

Local files (PDF/DOCX/PPTX/TXT/CSV/XLSX) can be placed in `kb/raw/` and indexed if needed.

## Licensing

This project is released under the MIT License (see LICENSE).
