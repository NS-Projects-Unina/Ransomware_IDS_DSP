#!/usr/bin/env python3

import argparse
import ipaddress
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

INPUT = Path("logs/network-behavioral-alerts.jsonl")
AUDIT = Path("logs/behavioral-response.jsonl")
GATEWAY = "ransomware_ids_honeypot-Gateaway-1"

ALLOWED_IP = ipaddress.ip_address("10.10.10.2")
MIN_SCORE = 70
REDIRECT_SECONDS = 60
MAX_ALERT_AGE = 30


def record(data):
    data["timestamp"] = datetime.now(timezone.utc).isoformat()
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(data) + "\n")
    print(json.dumps(data))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Applica il reindirizzamento; default dry-run"
    )
    args = parser.parse_args()

    if not INPUT.exists():
        raise SystemExit(f"File non trovato: {INPUT}")

    alerts = [
        json.loads(line)
        for line in INPUT.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    seen = set()

    for alert in alerts:
        if alert.get("event_type") != "network_behavioral_alert":
            continue

        try:
            alert_time = datetime.fromisoformat(
                alert["timestamp"].replace("Z", "+00:00")
            )
            age = (
                datetime.now(timezone.utc) -
                alert_time.astimezone(timezone.utc)
            ).total_seconds()
        except (KeyError, ValueError, TypeError):
            record({"decision": "rejected", "reason": "invalid_timestamp"})
            continue

        if age < 0 or age > MAX_ALERT_AGE:
            continue

        event_key = (
            alert.get("timestamp"),
            alert.get("src_ip"),
            alert.get("score")
        )

        if event_key in seen:
            continue

        seen.add(event_key)

        try:
            src = ipaddress.ip_address(alert["src_ip"])
            score = int(alert["score"])
        except (KeyError, ValueError, TypeError):
            record({"decision": "rejected", "reason": "invalid_alert"})
            continue

        if (
            src != ALLOWED_IP
            or score < MIN_SCORE
            or alert.get("attribution") != "application_log_src_ip"
        ):
            record({
                "decision": "rejected",
                "reason": "policy_not_satisfied",
                "src_ip": str(src),
                "score": score
            })
            continue

        if not args.apply:
            record({
                "decision": "dry-run",
                "src_ip": str(src),
                "score": score,
                "action": "would_redirect",
                "duration_seconds": REDIRECT_SECONDS
            })
            continue

        command = [
            "docker", "exec", "-u", "0", GATEWAY,
            "nft", "add", "element", "ip", "lab_redirect",
            "suspicious_v4", "{", str(src),
            "timeout", f"{REDIRECT_SECONDS}s", "}"
        ]

        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=10
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            record({
                "decision": "error",
                "src_ip": str(src),
                "error": str(exc)
            })
            continue

        record({
            "decision": "redirected" if result.returncode == 0 else "error",
            "src_ip": str(src),
            "score": score,
            "duration_seconds": REDIRECT_SECONDS,
            "error": result.stderr.strip() if result.returncode else None
        })


if __name__ == "__main__":
    main()
