"""
main.py — AI-Powered Cyber Defense System: Full Pipeline Runner
==========================================
Runs all 5 stages end-to-end on sample alert data and prints/saves the
final report for each. This is the single script you run live for the demo.

Usage:
    python3 main.py                      # run all sample_alerts.json through the pipeline
    python3 main.py --csv                # also run sample_alerts.csv batch
    python3 main.py --alert-id demo-008  # run just one alert (good for a focused demo)
    python3 main.py --mock               # force full mock mode (no live API calls at all)

Environment variables (all optional — pipeline runs in mock mode without them):
    GEMINI_API_KEY         -> enables live AI classification (Stage 3)
    ABUSEIPDB_API_KEY     -> enables live IP reputation (Stage 2)
    VIRUSTOTAL_API_KEY    -> enables live hash reputation (Stage 2)
    OTX_API_KEY           -> enables live domain reputation (Stage 2)
    CYBERDEFENSE_MOCK=1   -> forces mock mode for enrichment even if keys are set
"""

import argparse
import json
import os
import sys

from ingest import load_json_alerts, normalize_csv_batch
from enrich import enrich_alert
from classify import classify_alert
from report import generate_report
from orchestrate import orchestrate_response


def run_pipeline(envelope: dict) -> dict:
    """Runs one alert envelope through Stages 2-5 (Stage 1 already applied)."""
    print(f"\n{'='*70}")
    print(f"PROCESSING ALERT: {envelope['alert_id']}  (type: {envelope['alert_type']})")
    print(f"{'='*70}")

    print("\n--- STAGE 2: Threat Intel Enrichment ---")
    envelope = enrich_alert(envelope)

    print("\n--- STAGE 3: AI Classification ---")
    envelope = classify_alert(envelope)
    cls = envelope["classification"]
    print(f"  Severity: {cls.get('severity')} | Attack: {cls.get('attack_type')} "
          f"| Confidence: {cls.get('confidence_score')}")

    print("\n--- STAGE 4: Report Generation ---")
    report_path = generate_report(envelope)
    print(f"  Report saved: {report_path}")

    print("\n--- STAGE 5: Response Orchestration ---")
    envelope = orchestrate_response(envelope)

    return envelope


def main():
    parser = argparse.ArgumentParser(description="AI-Powered Cyber Defense System pipeline runner")
    parser.add_argument("--csv", action="store_true", help="Also process sample_alerts.csv batch")
    parser.add_argument("--alert-id", help="Only process the alert with this id (e.g. demo-008)")
    parser.add_argument("--mock", action="store_true", help="Force mock mode for enrichment")
    args = parser.parse_args()

    if args.mock:
        os.environ["CYBERDEFENSE_MOCK"] = "1"

    if not os.path.exists("sample_alerts.json"):
        print("ERROR: sample_alerts.json not found in current directory.")
        sys.exit(1)

    envelopes = load_json_alerts("sample_alerts.json")

    if args.csv and os.path.exists("sample_alerts.csv"):
        envelopes += normalize_csv_batch("sample_alerts.csv")

    if args.alert_id:
        envelopes = [e for e in envelopes if e["alert_id"] == args.alert_id]
        if not envelopes:
            print(f"No alert found with id '{args.alert_id}'")
            sys.exit(1)

    results = []
    for env in envelopes:
        result = run_pipeline(env)
        results.append(result)

    print(f"\n{'='*70}")
    print("PIPELINE RUN COMPLETE")
    print(f"{'='*70}")
    print(f"{'Alert ID':<12} {'Severity':<10} {'Attack Type':<22} {'Report'}")
    print("-" * 70)
    for r in results:
        cls = r["classification"]
        print(f"{r['alert_id']:<12} {cls.get('severity', '-'):<10} "
              f"{cls.get('attack_type', '-'):<22} {r['report_path']}")

    # Save a consolidated JSON of all results too, useful for judges to inspect
    with open("pipeline_run_summary.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull run summary saved to: pipeline_run_summary.json")


if __name__ == "__main__":
    main()
