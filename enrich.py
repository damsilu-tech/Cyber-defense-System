"""
Stage 2: Threat Intelligence Enrichment
==========================================
Enriches extracted indicators (IP, domain, hash) against free-tier
threat-intel APIs. Falls back to a deterministic MOCK MODE when an API
key is missing or a call fails, so the pipeline NEVER breaks on stage.

APIs used (all have free tiers):
  - AbuseIPDB   (IP reputation)         -> needs API key, free 1000 req/day
      Get one: https://www.abuseipdb.com/register  (free tier, no card needed)
  - VirusTotal  (hash / domain / URL)   -> needs API key, free 500 req/day (4/min)
      Get one: https://www.virustotal.com/gui/join-us (free "Public API" key)
  - AlienVault OTX (IOC / campaign tags)-> needs API key, free, generous limits
      Get one: https://otx.alienvault.com/ (sign up, key on your profile page)

Set these as environment variables before running live:
  ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, OTX_API_KEY

If any are unset, that specific lookup automatically falls back to mock
data (clearly labeled "mock": true in the output) rather than failing.
"""

import os
import hashlib
import requests

MOCK_MODE_FORCED = os.environ.get("CYBERDEFENSE_MOCK", "0") == "1"

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
OTX_KEY = os.environ.get("OTX_API_KEY")


def _deterministic_mock_score(indicator: str) -> int:
    """
    Generates a stable pseudo-random 'reputation score' 0-100 from the
    indicator string, so re-running the demo on the same sample data
    gives consistent, repeatable results (important for a live demo).
    """
    digest = hashlib.sha256(indicator.encode()).hexdigest()
    return int(digest[:4], 16) % 101


def enrich_ip(ip: str) -> dict:
    """Enrich an IP via AbuseIPDB. Falls back to mock if no key / call fails."""
    if not ip:
        return {}

    if ABUSEIPDB_KEY and not MOCK_MODE_FORCED:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()["data"]
            return {
                "indicator": ip,
                "type": "ip",
                "reputation_score": data.get("abuseConfidenceScore"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "total_reports": data.get("totalReports"),
                "mock": False,
                "source_api": "AbuseIPDB",
            }
        except Exception as e:
            # Fall through to mock on any failure (rate limit, network, etc.)
            print(f"[enrich_ip] live lookup failed for {ip}, using mock. ({e})")

    score = _deterministic_mock_score(ip)
    return {
        "indicator": ip,
        "type": "ip",
        "reputation_score": score,
        "country": "LK" if score % 2 == 0 else "RU",
        "isp": "Mock-ISP",
        "total_reports": score // 5,
        "mock": True,
        "source_api": "AbuseIPDB (mock)",
    }


def enrich_hash(file_hash: str) -> dict:
    """Enrich a file hash via VirusTotal. Falls back to mock if no key / call fails."""
    if not file_hash:
        return {}

    if VIRUSTOTAL_KEY and not MOCK_MODE_FORCED:
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                timeout=5,
            )
            resp.raise_for_status()
            attrs = resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return {
                "indicator": file_hash,
                "type": "hash",
                "reputation_score": round((malicious / total) * 100),
                "malware_family": (attrs.get("popular_threat_classification") or {})
                    .get("suggested_threat_label"),
                "detections": f"{malicious}/{total}",
                "mock": False,
                "source_api": "VirusTotal",
            }
        except Exception as e:
            print(f"[enrich_hash] live lookup failed for {file_hash}, using mock. ({e})")

    score = _deterministic_mock_score(file_hash)
    families = ["Emotet", "TrickBot", "LockBit", "AgentTesla", None]
    return {
        "indicator": file_hash,
        "type": "hash",
        "reputation_score": score,
        "malware_family": families[score % len(families)],
        "detections": f"{score // 2}/70",
        "mock": True,
        "source_api": "VirusTotal (mock)",
    }


def enrich_domain(domain: str) -> dict:
    """Enrich a domain via OTX. Falls back to mock if no key / call fails."""
    if not domain:
        return {}

    if OTX_KEY and not MOCK_MODE_FORCED:
        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": OTX_KEY},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            return {
                "indicator": domain,
                "type": "domain",
                "reputation_score": min(pulses * 10, 100),
                "pulse_count": pulses,
                "tags": [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:3]],
                "mock": False,
                "source_api": "AlienVault OTX",
            }
        except Exception as e:
            print(f"[enrich_domain] live lookup failed for {domain}, using mock. ({e})")

    score = _deterministic_mock_score(domain)
    return {
        "indicator": domain,
        "type": "domain",
        "reputation_score": score,
        "pulse_count": score // 10,
        "tags": ["c2-infrastructure"] if score > 70 else [],
        "mock": True,
        "source_api": "AlienVault OTX (mock)",
    }


def enrich_alert(envelope: dict) -> dict:
    """
    Stage 2 entry point. Takes a normalized alert envelope (from ingest.py),
    enriches every present indicator, and writes results into envelope["enrichment"].
    Returns the same envelope, mutated.
    """
    results = {}

    if envelope.get("src_ip"):
        results["src_ip"] = enrich_ip(envelope["src_ip"])
    if envelope.get("dst_ip"):
        results["dst_ip"] = enrich_ip(envelope["dst_ip"])
    if envelope.get("hash"):
        results["hash"] = enrich_hash(envelope["hash"])
    if envelope.get("domain"):
        results["domain"] = enrich_domain(envelope["domain"])

    envelope["enrichment"] = results
    return envelope


if __name__ == "__main__":
    import json
    test_env = {
        "src_ip": "185.220.101.4",
        "hash": "44d88612fea8a8f36de82e1278abb02f",
        "domain": "malicious-c2-example.net",
        "dst_ip": None,
    }
    print(json.dumps(enrich_alert(test_env), indent=2))
