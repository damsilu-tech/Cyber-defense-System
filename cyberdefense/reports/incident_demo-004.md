# Incident Report: demo-004

**Generated:** 2026-09-11T11:06:59.667519+00:00
**Alert Timestamp:** 2026-09-08T09:41:00Z
**Source:** SIEM-sim
**Alert Type:** login_success

---

## Summary

**Severity:** `Low`
**Attack Type:** Benign/False Positive
**AI Confidence Score:** 90/100
**MITRE ATT&CK Technique:** Not identified
**Classification Source:** Gemini API (live)

### AI Justification
> The alert represents a successful login event (login_success) between two private internal IP addresses (10.0.0.101 to 10.0.0.1). Both IP addresses have very low reputation scores (13 and 3), and standard internal authentication activity without malicious indicators strongly points to routine administrative or user behavior.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `10.0.0.101` |
| Destination IP | `10.0.0.1` |
| User | k.fernando |
| File Hash | `-` |
| Domain | `-` |
| URL | `-` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `10.0.0.101` | ip | 13 | AbuseIPDB (mock) | Yes |
| `10.0.0.1` | ip | 3 | AbuseIPDB (mock) | Yes |


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
