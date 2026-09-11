# Incident Report: demo-105

**Generated:** 2026-09-09T08:58:08.557550+00:00
**Alert Timestamp:** 2026-09-08T11:30:00Z
**Source:** IDS-batch
**Alert Type:** port_scan

---

## Summary

**Severity:** `Medium`
**Attack Type:** Reconnaissance
**AI Confidence Score:** 55/100
**MITRE ATT&CK Technique:** T1595 - Active Scanning
**Classification Source:** Mock/rule-based fallback

### AI Justification
> [MOCK CLASSIFIER - no live AI call made] Based on a maximum enrichment reputation score of 44, this alert was rule-mapped to Medium severity. Run with ANTHROPIC_API_KEY set for real AI-based classification.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `198.51.100.55` |
| Destination IP | `10.0.0.0` |
| User | - |
| File Hash | `-` |
| Domain | `-` |
| URL | `-` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `198.51.100.55` | ip | 44 | AbuseIPDB (mock) | Yes |
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
