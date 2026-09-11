"""
Stage 4: Automated Reporting
==========================================
Renders a clean, analyst-ready Markdown incident report from the fully
populated alert envelope (post ingest -> enrich -> classify -> respond).

Markdown is used because it's human-readable, diffable, version-controllable,
and trivially convertible to PDF (e.g. via pandoc) if a judge wants a hard copy:
  pandoc reports/incident_ALT-XXXX.md -o incident_ALT-XXXX.pdf
"""

import os
from datetime import datetime, timezone


def _fmt_enrichment_table(enrichment: dict) -> str:
    if not enrichment:
        return "_No indicators available for enrichment._\n"

    rows = ["| Indicator | Type | Reputation Score | Source | Mock? |",
            "|---|---|---|---|---|"]
    for _, data in enrichment.items():
        if not data:
            continue
        rows.append(
            f"| `{data.get('indicator', '-')}` "
            f"| {data.get('type', '-')} "
            f"| {data.get('reputation_score', '-')} "
            f"| {data.get('source_api', '-')} "
            f"| {'Yes' if data.get('mock') else 'No'} |"
        )
    return "\n".join(rows) + "\n"


def generate_report(envelope: dict, output_dir: str = "reports") -> str:
    """
    Stage 4 entry point. Builds a Markdown report from the envelope and
    writes it to output_dir/incident_<alert_id>.md. Returns the file path
    and also writes it into envelope["report_path"].
    """
    os.makedirs(output_dir, exist_ok=True)

    alert_id = envelope.get("alert_id", "UNKNOWN")
    cls = envelope.get("classification", {})
    enrichment = envelope.get("enrichment", {})
    response = envelope.get("response", {})
    generated_at = datetime.now(timezone.utc).isoformat()

    md = f"""# Incident Report: {alert_id}

**Generated:** {generated_at}
**Alert Timestamp:** {envelope.get('timestamp', '-')}
**Source:** {envelope.get('source', '-')}
**Alert Type:** {envelope.get('alert_type', '-')}

---

## Summary

**Severity:** `{cls.get('severity', 'UNCLASSIFIED')}`
**Attack Type:** {cls.get('attack_type', '-')}
**AI Confidence Score:** {cls.get('confidence_score', '-')}/100
**MITRE ATT&CK Technique:** {cls.get('mitre_technique') or 'Not identified'}
**Classification Source:** {'Mock/rule-based fallback' if cls.get('mock') else 'Gemini API (live)'}

### AI Justification
> {cls.get('justification', 'No classification available.')}

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `{envelope.get('src_ip') or '-'}` |
| Destination IP | `{envelope.get('dst_ip') or '-'}` |
| User | {envelope.get('user') or '-'} |
| File Hash | `{envelope.get('hash') or '-'}` |
| Domain | `{envelope.get('domain') or '-'}` |
| URL | `{envelope.get('url') or '-'}` |

---

## Threat Intelligence Enrichment

{_fmt_enrichment_table(enrichment)}

---

## Response Actions Taken

**Decision Matrix Tier:** {response.get('tier', '-')}

{response.get('summary', '_No response actions recorded._')}

---

## Recommended Actions

{response.get('recommended_actions', '- Review manually; no automated recommendation generated.')}

---

*This report was generated automatically by the AI-Powered Cyber Defense
System pipeline. Enrichment and/or classification marked "mock" indicates
simulated data used for demo purposes in place of a live API/AI call.*
"""

    file_path = os.path.join(output_dir, f"incident_{alert_id}.md")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(md)

    envelope["report_path"] = file_path
    return file_path


if __name__ == "__main__":
    test_env = {
        "alert_id": "ALT-TEST01",
        "timestamp": "2026-09-08T10:15:00Z",
        "source": "EDR-sim",
        "alert_type": "c2_beacon",
        "src_ip": "10.0.0.15",
        "dst_ip": "185.220.101.4",
        "user": "j.perera",
        "hash": None,
        "domain": "malicious-c2-example.net",
        "url": None,
        "enrichment": {
            "dst_ip": {"indicator": "185.220.101.4", "type": "ip", "reputation_score": 92,
                       "source_api": "AbuseIPDB (mock)", "mock": True},
        },
        "classification": {
            "severity": "Critical", "attack_type": "C2 Beaconing", "confidence_score": 88,
            "mitre_technique": "T1071.001 - Application Layer Protocol: Web Protocols",
            "justification": "Destination IP has a high abuse score and matches known C2 infrastructure tags.",
            "mock": True,
        },
        "response": {
            "tier": "Critical",
            "summary": "- Simulated IP block issued for `185.220.101.4`\n- Escalation ticket ESC-0001 created\n- Simulated on-call page sent",
            "recommended_actions": "- Isolate host 10.0.0.15 from network\n- Reset credentials for j.perera\n- Hunt for lateral movement from 10.0.0.15",
        },
    }
    path = generate_report(test_env)
    print(f"Report written to: {path}")
