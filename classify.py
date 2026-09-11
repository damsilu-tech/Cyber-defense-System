"""
Stage 3: AI-Based Classification (Google Gemini API)
==========================================
Sends the normalized + enriched alert to Gemini and asks for a STRICT JSON
verdict: severity, attack_type, confidence_score, MITRE technique, and a
short human-readable justification.

The system prompt below is the exact artifact to show judges — it is the
entire "AI integration" of this project, kept in one place and unmodified
at call time so it's easy to point to and explain live.

Requires: GEMINI_API_KEY environment variable (free tier via Google AI Studio,
no card required: https://aistudio.google.com/apikey).
If it's missing (or the call fails), falls back to a clearly-labeled
rule-based mock classifier so the demo still completes end-to-end.

DISCLOSURE NOTE: this stage uses Google's Gemini API. Update your
competition disclosure section to say so explicitly if your brief named a
specific AI provider — see README.
"""

import os
import json
import warnings
warnings.filterwarnings("ignore", message=".*AFC.*")

MODEL = "gemini-3.5-flash-lite"

# =====================================================================
# EXACT SYSTEM PROMPT USED FOR CLASSIFICATION (competition disclosure artifact)
# =====================================================================
SYSTEM_PROMPT = """You are a SOC (Security Operations Center) triage analyst assistant.
You will be given a normalized, enriched security alert as JSON. Your job is
to classify it and respond with STRICT JSON ONLY — no markdown, no code
fences, no preamble, no commentary outside the JSON object.

Output exactly this JSON shape:
{
  "severity": "Low" | "Medium" | "High" | "Critical",
  "attack_type": "<short attack category, e.g. 'C2 Beaconing', 'Credential Brute Force', 'Malware Execution', 'Phishing', 'Data Exfiltration', 'Reconnaissance', 'Benign/False Positive'>",
  "confidence_score": <integer 0-100>,
  "mitre_technique": "<MITRE ATT&CK technique ID and name if identifiable, e.g. 'T1071.001 - Application Layer Protocol: Web Protocols', else null>",
  "justification": "<2-3 sentences explaining the reasoning in plain analyst language, referencing specific fields from the alert/enrichment data>"
}

Classification guidance:
- Weigh enrichment reputation_score heavily: >80 strongly suggests malicious,
  <20 suggests benign, in between is ambiguous and should lower confidence_score.
- A "mock": true field in enrichment data means that indicator's reputation
  data is SIMULATED for demo purposes — treat it as valid input data anyway,
  but you may note in the justification that live-mode enrichment would be
  more authoritative.
- If indicators look internal/benign (private IP ranges, no hash, no
  enrichment hits) and alert_type suggests routine activity, classify as
  Low severity / Benign/False Positive with high confidence.
- confidence_score reflects YOUR certainty in the classification, not the
  severity itself.
- Respond with ONLY the JSON object. Nothing else.
"""
# =====================================================================


def _build_user_message(envelope: dict) -> str:
    """Builds the user-turn payload sent to Gemini: the alert + enrichment, trimmed."""
    payload = {
        "alert_id": envelope.get("alert_id"),
        "timestamp": envelope.get("timestamp"),
        "source": envelope.get("source"),
        "alert_type": envelope.get("alert_type"),
        "src_ip": envelope.get("src_ip"),
        "dst_ip": envelope.get("dst_ip"),
        "user": envelope.get("user"),
        "hash": envelope.get("hash"),
        "domain": envelope.get("domain"),
        "url": envelope.get("url"),
        "enrichment": envelope.get("enrichment", {}),
    }
    return json.dumps(payload, indent=2)


def _mock_classify(envelope: dict) -> dict:
    """
    Rule-based fallback classifier used only if GEMINI_API_KEY is missing
    or the live call fails. Clearly labeled as mock in the output.
    """
    enrichment = envelope.get("enrichment", {})
    scores = [v.get("reputation_score", 0) for v in enrichment.values() if v]
    max_score = max(scores) if scores else 0

    if max_score >= 85:
        severity, conf, attack = "Critical", 88, "C2 Beaconing"
        mitre = "T1071.001 - Application Layer Protocol: Web Protocols"
    elif max_score >= 65:
        severity, conf, attack = "High", 75, "Malware Execution"
        mitre = "T1204 - User Execution"
    elif max_score >= 35:
        severity, conf, attack = "Medium", 55, "Reconnaissance"
        mitre = "T1595 - Active Scanning"
    else:
        severity, conf, attack = "Low", 60, "Benign/False Positive"
        mitre = None

    return {
        "severity": severity,
        "attack_type": attack,
        "confidence_score": conf,
        "mitre_technique": mitre,
        "justification": (
            f"[MOCK CLASSIFIER - no live AI call made] Based on a maximum "
            f"enrichment reputation score of {max_score}, this alert was "
            f"rule-mapped to {severity} severity. Run with GEMINI_API_KEY "
            f"set for real AI-based classification."
        ),
        "mock": True,
    }


def classify_alert(envelope: dict, client=None) -> dict:
    """
    Stage 3 entry point. Sends envelope to Gemini for classification,
    parses strict JSON response, writes into envelope["classification"].
    Returns the same envelope, mutated.
    """
    api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key:
        print("[classify_alert] No GEMINI_API_KEY set - using mock classifier.")
        envelope["classification"] = _mock_classify(envelope)
        return envelope

    try:
        from google import genai                  # new SDK: pip install google-genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        user_msg = _build_user_message(envelope)

        response = client.models.generate_content(
            model=MODEL,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
            ),
            contents=user_msg,
        )

        raw_text = response.text.strip()
        # Defensive cleanup in case model wraps output in a code fence anyway
        raw_text = raw_text.replace("```json", "").replace("```", "").strip()

        result = json.loads(raw_text)
        result["mock"] = False
        envelope["classification"] = result

    except Exception as e:
        print(f"[classify_alert] live classification failed, using mock. ({e})")
        envelope["classification"] = _mock_classify(envelope)

    return envelope


if __name__ == "__main__":
    test_env = {
        "alert_id": "ALT-TEST01",
        "timestamp": "2026-09-08T10:15:00Z",
        "source": "EDR-sim",
        "alert_type": "c2_beacon",
        "src_ip": "10.0.0.15",
        "dst_ip": "185.220.101.4",
        "user": "j.perera",
        "hash": None,
        "domain": "malicious-c2-example.net",
        "url": None,
        "enrichment": {
            "dst_ip": {"reputation_score": 92, "mock": True},
            "domain": {"reputation_score": 88, "mock": True, "tags": ["c2-infrastructure"]},
        },
    }
    result = classify_alert(test_env)
    print(json.dumps(result["classification"], indent=2))