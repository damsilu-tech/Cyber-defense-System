# Incident Report: demo-102

**Generated:** 2026-09-09T08:58:08.556711+00:00
**Alert Timestamp:** 2026-09-08T11:05:00Z
**Source:** EDR-batch
**Alert Type:** malware_detection

---

## Summary

**Severity:** `Critical`
**Attack Type:** C2 Beaconing
**AI Confidence Score:** 88/100
**MITRE ATT&CK Technique:** T1071.001 - Application Layer Protocol: Web Protocols
**Classification Source:** Mock/rule-based fallback

### AI Justification
> [MOCK CLASSIFIER - no live AI call made] Based on a maximum enrichment reputation score of 88, this alert was rule-mapped to Critical severity. Run with ANTHROPIC_API_KEY set for real AI-based classification.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `10.0.0.61` |
| Destination IP | `-` |
| User | m.gunawardena |
| File Hash | `5f4dcc3b5aa765d61d8327deb882cf99` |
| Domain | `-` |
| URL | `-` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `10.0.0.61` | ip | 88 | AbuseIPDB (mock) | Yes |
| `5f4dcc3b5aa765d61d8327deb882cf99` | hash | 12 | VirusTotal (mock) | Yes |


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
