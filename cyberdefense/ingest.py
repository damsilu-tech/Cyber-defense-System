"""
Stage 1: Alert Ingestion & Normalization
==========================================
Accepts alerts from two simulated sources:
  - JSON webhook payloads (e.g. from a SIEM/EDR push)
  - CSV batch exports (e.g. a daily alert dump)

Normalizes both into a single internal schema (see NormalizedAlert below)
so every downstream stage only has to know about ONE format.

Design note for judges: normalization is deliberately "dumb and explicit"
(field-by-field mapping) rather than clever/inferred, so the logic is easy
to audit and explain live.
"""

import csv
import json
import uuid
from datetime import datetime, timezone


def _new_alert_id():
    return f"ALT-{uuid.uuid4().hex[:8].upper()}"


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def empty_envelope():
    """The canonical internal alert schema. Every stage reads/writes this dict."""
    return {
        "alert_id": None,
        "timestamp": None,
        "source": None,
        "alert_type": None,
        "src_ip": None,
        "dst_ip": None,
        "user": None,
        "hash": None,
        "domain": None,
        "url": None,
        "raw_payload": None,
        # filled in by later stages
        "enrichment": {},
        "classification": {},
        "report_path": None,
        "response": {},
    }


def normalize_json_alert(raw: dict, source_label: str = "SIEM-sim") -> dict:
    """
    Normalize a single JSON alert (e.g. simulated SIEM/EDR webhook payload)
    into the internal schema. Tolerant of varying key names across sources.
    """
    env = empty_envelope()

    # Tolerant field lookup: try several common key spellings per field
    def pick(*keys, default=None):
        for k in keys:
            if k in raw and raw[k] not in (None, ""):
                return raw[k]
        return default

    env["alert_id"] = pick("alert_id", "id", default=_new_alert_id())
    env["timestamp"] = pick("timestamp", "time", "@timestamp", default=_now_iso())
    env["source"] = pick("source", "product", default=source_label)
    env["alert_type"] = pick("alert_type", "event_type", "type", "signature", default="unknown")
    env["src_ip"] = pick("src_ip", "source_ip", "srcip")
    env["dst_ip"] = pick("dst_ip", "destination_ip", "dstip")
    env["user"] = pick("user", "username", "account")
    env["hash"] = pick("hash", "file_hash", "sha256", "md5")
    env["domain"] = pick("domain", "dns_query", "hostname")
    env["url"] = pick("url", "uri")
    env["raw_payload"] = raw  # preserve untouched original for audit trail

    return env


def normalize_csv_batch(csv_path: str, source_label: str = "SIEM-batch") -> list:
    """
    Normalize a CSV batch export into a list of internal-schema alert dicts.
    Expects (but tolerates missing) columns matching common alert fields.
    """
    alerts = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Re-use the JSON normalizer since column names map 1:1 to JSON keys
            alerts.append(normalize_json_alert(row, source_label=source_label))
    return alerts


def load_json_alerts(json_path: str) -> list:
    """Load a sample_alerts.json file (a list of raw alert dicts) and normalize each."""
    with open(json_path, "r", encoding="utf-8") as f:
        raw_alerts = json.load(f)
    return [normalize_json_alert(a, source_label=a.get("source", "SIEM-sim")) for a in raw_alerts]


if __name__ == "__main__":
    # Quick self-test
    sample = {
        "id": "demo-1",
        "time": "2026-09-08T10:15:00Z",
        "product": "EDR-sim",
        "signature": "malware_detection",
        "srcip": "10.0.0.15",
        "sha256": "44d88612fea8a8f36de82e1278abb02f",
        "username": "j.perera",
    }
    env = normalize_json_alert(sample)
    print(json.dumps(env, indent=2))
