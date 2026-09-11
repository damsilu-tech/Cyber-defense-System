# Incident Report: demo-103

**Generated:** 2026-09-09T08:58:08.557286+00:00
**Alert Timestamp:** 2026-09-08T11:12:00Z
**Source:** EDR-batch
**Alert Type:** c2_beacon

---

## Summary

**Severity:** `High`
**Attack Type:** Malware Execution
**AI Confidence Score:** 75/100
**MITRE ATT&CK Technique:** T1204 - User Execution
**Classification Source:** Mock/rule-based fallback

### AI Justification
> [MOCK CLASSIFIER - no live AI call made] Based on a maximum enrichment reputation score of 75, this alert was rule-mapped to High severity. Run with ANTHROPIC_API_KEY set for real AI-based classification.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `10.0.0.18` |
| Destination IP | `185.220.101.4` |
| User | - |
| File Hash | `-` |
| Domain | `malicious-c2-example.net` |
| URL | `-` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `10.0.0.18` | ip | 34 | AbuseIPDB (mock) | Yes |
| `185.220.101.4` | ip | 50 | AbuseIPDB (mock) | Yes |
| `malicious-c2-example.net` | domain | 75 | AlienVault OTX (mock) | Yes |


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
