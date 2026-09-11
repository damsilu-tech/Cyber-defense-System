# Incident Report: demo-101

**Generated:** 2026-09-09T08:58:08.556563+00:00
**Alert Timestamp:** 2026-09-08T11:00:00Z
**Source:** SIEM-batch
**Alert Type:** brute_force

---

## Summary

**Severity:** `Medium`
**Attack Type:** Reconnaissance
**AI Confidence Score:** 55/100
**MITRE ATT&CK Technique:** T1595 - Active Scanning
**Classification Source:** Mock/rule-based fallback

### AI Justification
> [MOCK CLASSIFIER - no live AI call made] Based on a maximum enrichment reputation score of 55, this alert was rule-mapped to Medium severity. Run with ANTHROPIC_API_KEY set for real AI-based classification.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `203.0.113.90` |
| Destination IP | `10.0.0.5` |
| User | admin |
| File Hash | `-` |
| Domain | `-` |
| URL | `-` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `203.0.113.90` | ip | 55 | AbuseIPDB (mock) | Yes |
| `10.0.0.5` | ip | 37 | AbuseIPDB (mock) | Yes |


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
