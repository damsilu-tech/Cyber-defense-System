# Deploying to Render

This folder is a single Flask web service: it serves `dashboard_live.html`
at `/` and exposes the real pipeline at `POST /api/run`. No separate
frontend hosting needed.

## 1. Push this folder to a GitHub repo
Render deploys from a git repo (or you can use "Public Git Repository" /
manual upload depending on your Render plan). Commit everything in this
folder, including `app.py`, `requirements.txt`, `Procfile`, and
`sample_alerts.json`.

## 2. Create the service on Render
Two options:

**Option A — Blueprint (fastest):**
1. In the Render dashboard: New -> Blueprint
2. Point it at this repo — it will read `render.yaml` and configure
   everything automatically.

**Option B — Manual Web Service:**
1. New -> Web Service -> connect this repo
2. Environment: `Python 3`
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `gunicorn app:app`

## 3. (Optional) Add API keys for live mode
By default the pipeline runs in the same clearly-labeled MOCK mode you've
been demoing with — nothing breaks without keys. To make Stage 2/3 actually
call live APIs, add these as environment variables in the Render service
settings (Environment tab):

| Key | Enables |
|---|---|
| `GEMINI_API_KEY` | Live AI classification (Stage 3) — https://aistudio.google.com/apikey |
| `ABUSEIPDB_API_KEY` | Live IP reputation (Stage 2) — https://www.abuseipdb.com/register |
| `VIRUSTOTAL_API_KEY` | Live hash reputation (Stage 2) — https://www.virustotal.com/gui/join-us |
| `OTX_API_KEY` | Live domain reputation (Stage 2) — https://otx.alienvault.com/ |

Leave any of these unset and that specific lookup automatically falls back
to mock data — the pipeline never breaks on a missing key.

## 4. Open it
Render gives you a URL like `https://cyberdefense-dashboard.onrender.com`.
Open it — that's the live dashboard, backed by the real pipeline.

## Notes
- **Free-tier disk is ephemeral.** `reports/`, `tickets/`, `escalations/`,
  and `logs/` get written to on each run but are wiped on redeploy/restart.
  Fine for a live demo; not for long-term storage.
- **Free-tier cold starts.** The free plan spins down after inactivity —
  the first request after idling can take ~30-50s while it wakes up. Hit
  `/health` a minute before you demo to warm it up.
- Running locally first is a good smoke test:
  ```
  pip install -r requirements.txt
  python app.py
  ```
  then open http://localhost:5000
