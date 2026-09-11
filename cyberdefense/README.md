# AI-Powered Cyber Defense System

A 5-stage automated pipeline that ingests security alerts, enriches them with
threat intelligence, classifies them using the Gemini API, generates
analyst-ready Markdown reports, and orchestrates a simulated response —
built as a solo competition entry.

## Architecture

```
Alert (JSON/CSV) → Ingest & Normalize → Threat Intel Enrichment →
AI Classification (Gemini) → Markdown Report → Response Orchestration
```

Every stage reads and writes a single shared dict (the "alert envelope"),
so any stage can be run, tested, or explained in isolation. See each file's
docstring for stage-specific detail.

| File | Stage | Purpose |
|---|---|---|
| `ingest.py` | 1 | Normalize JSON/CSV alerts into one internal schema |
| `enrich.py` | 2 | Look up IP/domain/hash reputation (live or mock) |
| `classify.py` | 3 | Send alert to Gemini for severity/attack classification |
| `report.py` | 4 | Render a Markdown incident report |
| `orchestrate.py` | 5 | Run severity → action decision matrix (simulated) |
| `main.py` | — | Runs all 8 sample alerts through the full pipeline |

## Setup

```bash
pip install requests google-genai
```

(Only `requests` is needed for mock-mode demo. `google-genai` is only
imported when `GEMINI_API_KEY` is set, so the pipeline runs without it installed.)

### API Keys (all optional — pipeline runs fully in mock mode without any of them)

| Service | Used for | Free tier | Get a key |
|---|---|---|---|
| Google Gemini | AI classification (Stage 3) | Free tier, no card required | https://aistudio.google.com/apikey |
| AbuseIPDB | IP reputation (Stage 2) | 1,000 req/day, free, no card | https://www.abuseipdb.com/register |
| VirusTotal | Hash reputation (Stage 2) | 500 req/day / 4 req/min, free | https://www.virustotal.com/gui/join-us |
| AlienVault OTX | Domain/campaign tags (Stage 2) | Free, generous limits | https://otx.alienvault.com |

Set whichever you have as environment variables:

```bash
export GEMINI_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export VIRUSTOTAL_API_KEY="..."
export OTX_API_KEY="..."
```

**Note on model name:** `classify.py` currently targets `gemini-3.5-flash-lite`
via the `google-genai` SDK (the older `google-generativeai` package reached
end-of-life on Nov 30, 2025 — don't install it). Google updates available
model names periodically — check https://aistudio.google.com for the
current free-tier model list before your demo and update the `MODEL`
constant in `classify.py` if it's changed again.

Any key you don't set simply causes that one lookup to fall back to a
clearly-labeled (`"mock": true`) deterministic mock value — nothing breaks.

## Running the Demo

```bash
# Full pipeline, all 8 sample alerts (uses live APIs for any key you've set)
python3 main.py

# Force full mock mode regardless of keys (safest for an offline demo room)
python3 main.py --mock

# Also run the CSV batch ingestion path
python3 main.py --csv

# Run just one alert — good for a focused walkthrough with judges
python3 main.py --alert-id demo-008
```

Each run prints stage-by-stage progress to the console, writes a Markdown
report per alert to `reports/`, writes mock tickets/escalations to
`tickets/`/`escalations/`, appends to `logs/alerts.log`, and saves a
consolidated `pipeline_run_summary.json`.

**Recommended demo flow:** run `python3 main.py --alert-id demo-008` live
(a ransomware alert that triggers the High tier), then open the generated
`reports/incident_demo-008.md` to walk judges through the full trail from
raw alert to AI verdict to simulated response.

## Disclosure (Competition Compliance)

**Tools/services used, all disclosed:**
- Python 3 (standard library: `csv`, `json`, `uuid`, `datetime`, `os`, `argparse`, `hashlib`)
- `requests` (HTTP calls to threat-intel APIs)
- `google-genai` Python SDK (Google Gemini API access), model: `gemini-3.5-flash-lite`
- AbuseIPDB REST API (IP reputation) — free tier
- VirusTotal REST API (file hash reputation) — free tier
- AlienVault OTX REST API (domain/campaign intel) — free tier

**Disclosure note:** this system uses the **Google Gemini API** (model `gemini-3.5-flash-lite`, set via `classify.py`) for all AI classification. If your competition brief named a different provider, update your submission notes to explicitly call out Gemini — judges compare disclosure against what's actually running, and mismatches here are an easy, avoidable deduction.

**No undisclosed or black-box components.** All classification logic is a
single documented system prompt (see `classify.py`, `SYSTEM_PROMPT`), and
all response actions are simulated — none of them make real calls to
firewall, EDR, or paging infrastructure. This is enforced in code (functions
prefixed `simulate_`) and printed to the console/log at runtime so it's
verifiable live.

**Mock mode:** every stage that depends on an external API degrades
gracefully to a clearly labeled mock/rule-based fallback if a key is
missing or a call fails, so a venue with no/unstable internet cannot break
the demo.

## Judge Talking Points

> This system automates the first-line triage work a SOC analyst does
> manually: normalizing alerts from different tools into one format,
> enriching indicators against real threat-intel sources, using Google's
> Gemini API to reason about severity and attack type the way an analyst would (with a
> single auditable system prompt rather than a black box), generating a
> report ready to hand to a human, and then executing a disclosed,
> simulated response matrix — all fully automated end-to-end, but built so
> every stage can run, fail gracefully, and be explained independently,
> which is why it stays demoable even without live internet access.

## Project Structure

```
cyberdefense/
├── ingest.py
├── enrich.py
├── classify.py
├── report.py
├── orchestrate.py
├── main.py
├── sample_alerts.json
├── sample_alerts.csv
├── reports/            (generated)
├── tickets/             (generated)
├── escalations/         (generated)
├── logs/alerts.log      (generated)
└── pipeline_run_summary.json  (generated)
```
