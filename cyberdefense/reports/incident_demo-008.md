# Incident Report: demo-008

**Generated:** 2026-09-11T11:07:16.834086+00:00
**Alert Timestamp:** 2026-09-08T10:18:00Z
**Source:** EDR-sim
**Alert Type:** ransomware_behavior

---

## Summary

**Severity:** `Critical`
**Attack Type:** Malware Execution
**AI Confidence Score:** 95/100
**MITRE ATT&CK Technique:** T1486 - Data Encrypted for Impact
**Classification Source:** Gemini API (live)

### AI Justification
> The alert is triggered by ransomware behavior associated with user r.bandara on a local host. The file hash (e99a18c428cb38d5f260853678922e03) has a high reputation score of 82 and is identified as belonging to the LockBit malware family with 41/70 detections. Additionally, the destination IP has a notable reputation score of 78, and the domain indicates a ransomware C2 payment portal.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `10.0.0.44` |
| Destination IP | `91.219.237.244` |
| User | r.bandara |
| File Hash | `e99a18c428cb38d5f260853678922e03` |
| Domain | `ransom-c2-payment.onion.link` |
| URL | `-` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `10.0.0.44` | ip | 7 | AbuseIPDB (mock) | Yes |
| `91.219.237.244` | ip | 78 | AbuseIPDB (mock) | Yes |
| `e99a18c428cb38d5f260853678922e03` | hash | 82 | VirusTotal (mock) | Yes |
| `ransom-c2-payment.onion.link` | domain | 66 | AlienVault OTX (mock) | Yes |


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
