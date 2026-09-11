"""
app.py — Flask backend for the AI-Powered Cyber Defense System GUI
==========================================
Wraps the real 5-stage pipeline (ingest -> enrich -> classify -> report ->
orchestrate) behind a small HTTP API so dashboard_live.html can drive the
ACTUAL Python pipeline via fetch(), instead of simulating it in JS.

This does not change how the pipeline works: it calls the exact same
functions main.py calls. Live vs mock behavior for enrichment/classification
is still controlled entirely by the environment variables documented in
main.py / enrich.py / classify.py (GEMINI_API_KEY, ABUSEIPDB_API_KEY,
VIRUSTOTAL_API_KEY, OTX_API_KEY, CYBERDEFENSE_MOCK). Set those as Render
environment variables to go live; leave them unset and it runs in the
same clearly-labeled mock mode as before.

Endpoints:
  GET  /                  -> serves dashboard_live.html
  GET  /health            -> health check (used by Render)
  GET  /api/sample-alerts -> returns sample_alerts.json for the "Load Sample" button
  POST /api/run           -> runs one alert through the full pipeline, returns
                              the populated envelope + rendered report markdown

Run locally:
    pip install -r requirements.txt
    python app.py            # http://localhost:5000

Deploy on Render:
    See DEPLOY.md
"""

import json
import os

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from classify import classify_alert
from enrich import enrich_alert
from ingest import normalize_json_alert
from orchestrate import orchestrate_response
from report import generate_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
CORS(app)  # allow the dashboard to be hosted separately from the API if needed


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/api/sample-alerts")
def sample_alerts():
    path = os.path.join(BASE_DIR, "sample_alerts.json")
    if not os.path.exists(path):
        return jsonify([]), 404
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return jsonify(data)


@app.post("/api/run")
def run_alert():
    """
    Body: a raw alert JSON object (any of the shapes ingest.py tolerates),
    optionally wrapped as {"alert": {...}}.
    Runs Stages 1-5 for real and returns the fully populated envelope.
    """
    try:
        raw = request.get_json(force=True, silent=True)
        if raw is None:
            return jsonify(error="Request body must be valid JSON."), 400
        if isinstance(raw, dict) and isinstance(raw.get("alert"), dict):
            raw = raw["alert"]
        if not isinstance(raw, dict) or not raw:
            return jsonify(error="Alert JSON must be a non-empty object."), 400

        # Stage 1: Ingest
        envelope = normalize_json_alert(raw, source_label=raw.get("source", "GUI-live"))

        # Stage 2: Enrich
        envelope = enrich_alert(envelope)

        # Stage 3: Classify
        envelope = classify_alert(envelope)

        # Stage 4: Report
        report_path = generate_report(envelope)
        report_markdown = ""
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                report_markdown = f.read()
        except OSError:
            pass

        # Stage 5: Respond
        envelope = orchestrate_response(envelope)

        return jsonify(
            alert_id=envelope.get("alert_id"),
            timestamp=envelope.get("timestamp"),
            source=envelope.get("source"),
            alert_type=envelope.get("alert_type"),
            src_ip=envelope.get("src_ip"),
            dst_ip=envelope.get("dst_ip"),
            user=envelope.get("user"),
            hash=envelope.get("hash"),
            domain=envelope.get("domain"),
            url=envelope.get("url"),
            enrichment=envelope.get("enrichment", {}),
            classification=envelope.get("classification", {}),
            response=envelope.get("response", {}),
            report_path=report_path,
            report_markdown=report_markdown,
        )

    except Exception as e:  # noqa: BLE001 - surface pipeline errors to the GUI
        app.logger.exception("Pipeline run failed")
        return jsonify(error=str(e)), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
