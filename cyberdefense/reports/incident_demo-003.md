# Incident Report: demo-003

**Generated:** 2026-09-11T11:06:56.288864+00:00
**Alert Timestamp:** 2026-09-08T09:35:00Z
**Source:** EDR-sim
**Alert Type:** malware_detection

---

## Summary

**Severity:** `High`
**Attack Type:** Malware Execution
**AI Confidence Score:** 85/100
**MITRE ATT&CK Technique:** T1204 - User Execution
**Classification Source:** Gemini API (live)

### AI Justification
> The alert indicates a malware detection for user n.silva on internal IP 10.0.0.22 with a known Emotet malware hash. Although the mock VirusTotal score reports 0 detections, the file hash is explicitly tagged with the 'Emotet' malware family and the source IP exhibits an elevated reputation score of 71 associated with Russian infrastructure.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `10.0.0.22` |
| Destination IP | `-` |
| User | n.silva |
| File Hash | `44d88612fea8a8f36de82e1278abb02f` |
| Domain | `-` |
| URL | `-` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `10.0.0.22` | ip | 71 | AbuseIPDB (mock) | Yes |
| `44d88612fea8a8f36de82e1278abb02f` | hash | 0 | VirusTotal (mock) | Yes |


---

## Response Actions Taken

**Decision Matrix Tier:** -

_No response actions recorded._

---

## Recommended Actions

- Review manually; no automated recommendation generated.

---

*This report was generated automatically by the AI-Powered Cyber Defense
System pipeline. Enrichment and/or classification marked "mock" indicates
simulated data used for demo purposes in place of a live API/AI call.*
