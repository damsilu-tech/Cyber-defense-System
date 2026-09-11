"""
Stage 5: Response Orchestration
==========================================
Implements the severity -> action decision matrix. ALL actions here are
SIMULATED: they print a structured "action taken" log line and write a
mock artifact (ticket/escalation JSON) to disk. Nothing here makes a real
network call to firewall/EDR/paging infrastructure. This is deliberate and
disclosed for competition compliance.

Decision matrix:
  Low       -> log only
  Medium    -> log + simulate analyst notification
  High      -> log + simulate host isolation + create mock ticket
  Critical  -> log + simulate IP block + escalate + simulate on-call page
"""

import os
import json
import uuid
from datetime import datetime, timezone

LOG_DIR = "logs"
TICKET_DIR = "tickets"
ESCALATION_DIR = "escalations"


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _log(message: str):
    os.makedirs(LOG_DIR, exist_ok=True)
    line = f"[{_now_iso()}] {message}"
    print(line)
    with open(os.path.join(LOG_DIR, "alerts.log"), "a", encoding="utf-8") as f:
        f.write(line + "\n")


def simulate_analyst_notification(envelope: dict):
    _log(f"SIMULATED NOTIFY: analyst paged (Slack/email mock) re: {envelope['alert_id']}")
    return {"channel": "mock-slack", "message": f"New Medium alert: {envelope['alert_id']}"}


def simulate_host_isolation(envelope: dict):
    target = envelope.get("src_ip") or envelope.get("user") or "unknown-host"
    _log(f"SIMULATED ACTION: host isolation command issued for {target} (NOT executed against real EDR)")
    return {"action": "isolate_host", "target": target, "executed": False}


def simulate_ip_block(envelope: dict):
    target = envelope.get("dst_ip") or envelope.get("src_ip") or "unknown-ip"
    _log(f"SIMULATED ACTION: firewall block rule issued for {target} (NOT executed against real firewall)")
    return {"action": "block_ip", "target": target, "executed": False}


def simulate_oncall_page(envelope: dict):
    _log(f"SIMULATED PAGE: on-call engineer paged (mock PagerDuty) re: {envelope['alert_id']}")
    return {"paged": True, "channel": "mock-pagerduty"}


def create_mock_ticket(envelope: dict) -> str:
    os.makedirs(TICKET_DIR, exist_ok=True)
    ticket_id = f"TICKET-{uuid.uuid4().hex[:6].upper()}"
    ticket = {
        "ticket_id": ticket_id,
        "alert_id": envelope["alert_id"],
        "created_at": _now_iso(),
        "severity": envelope["classification"].get("severity"),
        "summary": envelope["classification"].get("attack_type"),
        "status": "open",
    }
    path = os.path.join(TICKET_DIR, f"{ticket_id}.json")
    with open(path, "w") as f:
        json.dump(ticket, f, indent=2)
    _log(f"Mock ticket created: {ticket_id} ({path})")
    return ticket_id


def create_escalation(envelope: dict) -> str:
    os.makedirs(ESCALATION_DIR, exist_ok=True)
    esc_id = f"ESC-{uuid.uuid4().hex[:6].upper()}"
    escalation = {
        "escalation_id": esc_id,
        "alert_id": envelope["alert_id"],
        "created_at": _now_iso(),
        "severity": envelope["classification"].get("severity"),
        "reason": envelope["classification"].get("justification"),
        "status": "escalated",
    }
    path = os.path.join(ESCALATION_DIR, f"{esc_id}.json")
    with open(path, "w") as f:
        json.dump(escalation, f, indent=2)
    _log(f"Escalation created: {esc_id} ({path})")
    return esc_id


RECOMMENDED_ACTIONS = {
    "Low": "- No action required beyond logging.\n- Revisit if similar alerts cluster within 24h.",
    "Medium": "- Analyst should review within shift.\n- Correlate with related alerts from same source/user.",
    "High": "- Confirm host isolation with EDR team.\n- Reset affected user credentials.\n- Begin lateral-movement hunt from source host.",
    "Critical": "- Confirm IP block at perimeter firewall.\n- Initiate incident response process.\n- Notify affected system owners and legal/compliance if data exposure suspected.",
}


def orchestrate_response(envelope: dict) -> dict:
    """
    Stage 5 entry point. Reads envelope['classification']['severity'],
    runs the matching simulated actions, and writes a summary into
    envelope['response']. Returns the same envelope, mutated.
    """
    severity = envelope.get("classification", {}).get("severity", "Low")
    actions_log = []

    _log(f"Processing {envelope.get('alert_id')} at severity={severity}")

    if severity == "Low":
        actions_log.append("Logged only. No further action taken.")

    elif severity == "Medium":
        notif = simulate_analyst_notification(envelope)
        actions_log.append(f"Analyst notified (mock): {notif['message']}")

    elif severity == "High":
        iso = simulate_host_isolation(envelope)
        ticket_id = create_mock_ticket(envelope)
        actions_log.append(f"Simulated isolation of `{iso['target']}`")
        actions_log.append(f"Ticket created: {ticket_id}")

    elif severity == "Critical":
        block = simulate_ip_block(envelope)
        esc_id = create_escalation(envelope)
        page = simulate_oncall_page(envelope)
        actions_log.append(f"Simulated IP block on `{block['target']}`")
        actions_log.append(f"Escalation created: {esc_id}")
        actions_log.append(f"On-call paged: {page['paged']}")

    envelope["response"] = {
        "tier": severity,
        "summary": "\n".join(f"- {a}" for a in actions_log),
        "recommended_actions": RECOMMENDED_ACTIONS.get(severity, "- Manual review recommended."),
    }
    return envelope


if __name__ == "__main__":
    test_env = {
        "alert_id": "ALT-TEST01",
        "src_ip": "10.0.0.15",
        "dst_ip": "185.220.101.4",
        "classification": {"severity": "Critical", "attack_type": "C2 Beaconing",
                            "justification": "High reputation score match on known C2 infra."},
    }
    result = orchestrate_response(test_env)
    print(json.dumps(result["response"], indent=2))
