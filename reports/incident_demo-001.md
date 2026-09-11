# Incident Report: demo-001

**Generated:** 2026-09-11T11:06:49.888921+00:00
**Alert Timestamp:** 2026-09-08T09:12:00Z
**Source:** EDR-sim
**Alert Type:** c2_beacon

---

## Summary

**Severity:** `High`
**Attack Type:** C2 Beaconing
**AI Confidence Score:** 90/100
**MITRE ATT&CK Technique:** T1071.001 - Application Layer Protocol: Web Protocols
**Classification Source:** Gemini API (live)

### AI Justification
> The alert type explicitly indicates a C2 beacon, and the associated domain 'malicious-c2-example.net' has a high reputation score of 75 with the 'c2-infrastructure' tag in AlienVault OTX. Furthermore, the source IP 10.0.0.15 shows a high simulated reputation score of 85, reinforcing malicious activity. Although the enrichment data is marked as mock, the indicators strongly align with command and control behavior.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `10.0.0.15` |
| Destination IP | `185.220.101.4` |
| User | j.perera |
| File Hash | `-` |
| Domain | `malicious-c2-example.net` |
| URL | `-` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `10.0.0.15` | ip | 85 | AbuseIPDB (mock) | Yes |
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
