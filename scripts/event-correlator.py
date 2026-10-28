#!/usr/bin/env python3

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument(
    "--base-dir",
    default="results/validation-v2"
)
parser.add_argument(
    "--suricata-log",
    default="logs/suricata/eve.json"
)
args = parser.parse_args()

BASE = Path(args.base_dir)
SURICATA_LOG = Path(args.suricata_log)
WINDOW_SECONDS = 30

def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)

def load_jsonl(path):
    if not path.exists():
        return []
    events = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    print(
                        f"WARNING: record JSON non valido in {path}, "
                        f"riga {len(events) + 1}: {exc}"
                    )
    return events

network = load_jsonl(BASE / "network-alerts.jsonl")
responses = load_jsonl(BASE / "network-responses.jsonl")
filesystem = load_jsonl(BASE / "filesystem-alerts.jsonl")
suricata = [
    event for event in load_jsonl(SURICATA_LOG)
    if event.get("event_type") == "alert"
]

responses_by_id = {
    event["event_id"]: event
    for event in responses
    if event.get("event_id")
}

correlated = []

for alert in network:
    alert_time = parse_time(alert["timestamp"])
    src_ip = alert.get("src_ip")

    related_suricata = []
    for event in suricata:
        if event.get("src_ip") != src_ip:
            continue
        delta = abs((parse_time(event["timestamp"]) - alert_time).total_seconds())
        if delta <= WINDOW_SECONDS:
            related_suricata.append({
                "timestamp": event["timestamp"],
                "signature_id": event.get("alert", {}).get("signature_id"),
                "action": event.get("alert", {}).get("action"),
                "time_delta_seconds": round(delta, 3),
            })

    related_filesystem = []
    for event in filesystem:
        delta = abs((parse_time(event["timestamp"]) - alert_time).total_seconds())
        if delta <= WINDOW_SECONDS:
            related_filesystem.append({
                "timestamp": event["timestamp"],
                "score": event.get("score"),
                "time_delta_seconds": round(delta, 3),
                "attribution": "unattributed",
            })

    response = responses_by_id.get(alert.get("event_id"))

    correlated.append({
        "event_type": "correlated_evidence",
        "event_id": alert.get("event_id"),
        "timestamp": alert["timestamp"],
        "src_ip": src_ip,
        "network_detection_mode": alert.get("detection_mode"),
        "network_score": alert.get("score"),
        "response_decision": response.get("decision") if response else None,
        "suricata_alerts": related_suricata,
        "filesystem_alerts": related_filesystem,
        "correlation_window_seconds": WINDOW_SECONDS,
        "network_attribution": alert.get("attribution"),
        "filesystem_attribution": "not_established",
        "causal_link_established": False,
    })

output = BASE / "correlated-evidence.jsonl"
with output.open("w", encoding="utf-8") as f:
    for event in correlated:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

print("Network alerts:", len(network))
print("Suricata alerts:", len(suricata))
print("Filesystem alerts:", len(filesystem))
print("Correlated records:", len(correlated))
print("Records with Suricata matches:",
      sum(bool(e["suricata_alerts"]) for e in correlated))
print("Records with filesystem matches:",
      sum(bool(e["filesystem_alerts"]) for e in correlated))
print("Output:", output)
