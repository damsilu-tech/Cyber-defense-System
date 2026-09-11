# Incident Report: demo-005

**Generated:** 2026-09-11T11:07:04.002973+00:00
**Alert Timestamp:** 2026-09-08T09:50:00Z
**Source:** EmailGateway-sim
**Alert Type:** phishing_link_clicked

---

## Summary

**Severity:** `Medium`
**Attack Type:** Phishing
**AI Confidence Score:** 75/100
**MITRE ATT&CK Technique:** T1566.002 - Phishing: Spearphishing Link
**Classification Source:** Gemini API (live)

### AI Justification
> User a.jayasinghe clicked a suspicious URL on a newly registered domain ('secure-login-update-verify.com') characteristic of credential harvesting. Although the domain's reputation score of 33 is ambiguous, the URL structure strongly indicates a credential update phishing lure.

---

## Indicators of Compromise (IOCs)

| Field | Value |
|---|---|
| Source IP | `10.0.0.77` |
| Destination IP | `-` |
| User | a.jayasinghe |
| File Hash | `-` |
| Domain | `secure-login-update-verify.com` |
| URL | `http://secure-login-update-verify.com/reset` |

---

## Threat Intelligence Enrichment

| Indicator | Type | Reputation Score | Source | Mock? |
|---|---|---|---|---|
| `10.0.0.77` | ip | 9 | AbuseIPDB (mock) | Yes |
| `secure-login-update-verify.com` | domain | 33 | AlienVault OTX (mock) | Yes |


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
