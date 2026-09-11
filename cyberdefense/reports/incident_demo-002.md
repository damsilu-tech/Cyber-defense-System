# Incident Report: demo-002

**Generated:** 2026-09-11T11:06:53.147243+00:00
**Alert Timestamp:** 2026-09-08T09:20:00Z
**Source:** SIEM-sim
**Alert Type:** brute_force

---

## Summary

**Severity:** `Medium`
**Attack Type:** Credential Brute Force
**AI Confidence Score:** 65/100
**MITRE ATT&CK Technique:** T1110 - Brute Force
**Classification Source:** Gemini API (live)

### AI Justification
> The alert indicates a brute force attempt targeting the 'admin' account from source IP 203.0.113.44. The enrichment reputation scores for both source and destination IPs are ambiguous (32 and 37 respectively), resulting in a moderate confidence score while maintaining a medium severity due to the high-value target account.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `203.0.113.44` |
| Destination IP | `10.0.0.5` |
| User | admin |
| File Hash | `-` |
| Domain | `-` |
| URL | `-` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `203.0.113.44` | ip | 32 | AbuseIPDB (mock) | Yes |
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
