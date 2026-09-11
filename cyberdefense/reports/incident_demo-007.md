# Incident Report: demo-007

**Generated:** 2026-09-11T11:07:12.954132+00:00
**Alert Timestamp:** 2026-09-08T10:10:00Z
**Source:** IDS-sim
**Alert Type:** port_scan

---

## Summary

**Severity:** `Low`
**Attack Type:** Reconnaissance
**AI Confidence Score:** 60/100
**MITRE ATT&CK Technique:** T1595 - Active Scanning
**Classification Source:** Gemini API (live)

### AI Justification
> The alert indicates a port scan originating from an external IP address (198.51.100.23) toward an internal destination. However, the moderate reputation score of 45 and low total reports suggest ambiguous or low-severity reconnaissance activity rather than an active breach.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `198.51.100.23` |
| Destination IP | `10.0.0.0` |
| User | - |
| File Hash | `-` |
| Domain | `-` |
| URL | `-` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `198.51.100.23` | ip | 45 | AbuseIPDB (mock) | Yes |
| `10.0.0.0` | ip | 21 | AbuseIPDB (mock) | Yes |


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
