# Incident Report: demo-006

**Generated:** 2026-09-11T11:07:07.569105+00:00
**Alert Timestamp:** 2026-09-08T10:02:00Z
**Source:** DLP-sim
**Alert Type:** large_data_transfer

---

## Summary

**Severity:** `Medium`
**Attack Type:** Data Exfiltration
**AI Confidence Score:** 60/100
**MITRE ATT&CK Technique:** T1048 - Exfiltration Over Alternative Protocol
**Classification Source:** Gemini API (live)

### AI Justification
> The alert highlights a large data transfer initiated by the service account 'svc-backup' to an external IP address (45.33.32.156) with a moderate reputation score of 48. Although the indicators are mocked and the destination reputation is ambiguous, the behavior pattern warrants a medium severity classification for potential unauthorized data exfiltration.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `10.0.0.30` |
| Destination IP | `45.33.32.156` |
| User | svc-backup |
| File Hash | `-` |
| Domain | `-` |
| URL | `-` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `10.0.0.30` | ip | 12 | AbuseIPDB (mock) | Yes |
| `45.33.32.156` | ip | 48 | AbuseIPDB (mock) | Yes |


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
