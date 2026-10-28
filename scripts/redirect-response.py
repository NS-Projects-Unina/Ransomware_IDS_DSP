#!/usr/bin/env python3

import argparse
import ipaddress
import json
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

EVE = Path("logs/suricata/eve.json")
AUDIT = Path("logs/redirect-response.jsonl")
GATEWAY = "ransomware_ids_honeypot-Gateaway-1"

SRC_OK = ipaddress.ip_address("10.10.10.2")
DST_OK = ipaddress.ip_address("10.20.20.2")
SID = 1000004
DEST_PORT = 8081

THRESHOLD = 1
WINDOW = 10
REDIRECT_SECONDS = 60

recent = defaultdict(deque)
redirected_until = {}


def audit(data):
    data["timestamp"] = datetime.now(timezone.utc).isoformat()
    AUDIT.parent.mkdir(parents=True, exist_ok=True)

    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(data) + "\n")

    print(json.dumps(data), flush=True)


def redirect_ip(src):
    cmd = [
        "docker", "exec", "-u", "0", GATEWAY,
        "nft", "add", "element", "ip", "lab_redirect",
        "suspicious_v4", "{", str(src), "timeout",
        f"{REDIRECT_SECONDS}s", "}"
    ]

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=10
    )

    if result.returncode:
        audit({
            "decision": "error",
            "action": "redirect_failed",
            "src_ip": str(src),
            "error": result.stderr.strip()
        })
        return False

    redirected_until[src] = time.monotonic() + REDIRECT_SECONDS

    audit({
        "decision": "redirected",
        "action": "temporary_redirect",
        "src_ip": str(src),
        "duration_seconds": REDIRECT_SECONDS
    })
    return True


def process(event, dry_run):
    if event.get("event_type") != "alert":
        return

    alert = event.get("alert", {})

    if alert.get("signature_id") != SID:
        return

    try:
        src = ipaddress.ip_address(event["src_ip"])
        dst = ipaddress.ip_address(event["dest_ip"])
    except (KeyError, ValueError):
        audit({"decision": "reject", "reason": "invalid_ip"})
        return

    if (
        src != SRC_OK
        or dst != DST_OK
        or event.get("dest_port") != DEST_PORT
    ):
        audit({
            "decision": "reject",
            "reason": "outside_policy",
            "src_ip": str(src),
            "dest_ip": str(dst)
        })
        return

    now = time.monotonic()
    events = recent[src]
    events.append(now)

    while events and now - events[0] > WINDOW:
        events.popleft()

    audit({
        "decision": "observed",
        "src_ip": str(src),
        "signature_id": SID,
        "count_in_window": len(events),
        "threshold": THRESHOLD,
        "window_seconds": WINDOW
    })

    if len(events) < THRESHOLD:
        return

    if redirected_until.get(src, 0) > now:
        return

    events.clear()

    if dry_run:
        audit({
            "decision": "dry-run",
            "action": "would_redirect_source",
            "src_ip": str(src),
            "duration_seconds": REDIRECT_SECONDS
        })
    else:
        redirect_ip(src)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not EVE.exists():
        raise SystemExit(f"EVE non trovato: {EVE}")

    if not args.dry_run:
        check = subprocess.run(
            [
                "docker", "exec", "-u", "0", GATEWAY,
                "nft", "list", "set", "ip",
                "lab_redirect", "suspicious_v4"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        if check.returncode:
            raise SystemExit(
                "Set nftables suspicious_v4 non disponibile."
            )

    print(
        f"Redirect responder "
        f"{'DRY-RUN' if args.dry_run else 'ATTIVO'}; "
        f"soglia {THRESHOLD}/{WINDOW}s, "
        f"deviazione {REDIRECT_SECONDS}s.",
        flush=True
    )

    with EVE.open(encoding="utf-8") as f:
        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.25)
                continue

            try:
                process(json.loads(line), args.dry_run)
            except json.JSONDecodeError:
                continue


if __name__ == "__main__":
    main()
