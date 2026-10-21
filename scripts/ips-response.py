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
AUDIT = Path("logs/ips-response.jsonl")
GATEWAY = "ransomware_ids_honeypot-Gateaway-1"

SRC_OK = ipaddress.ip_address("10.10.10.2")
DST_OK = ipaddress.ip_address("10.20.20.2")
SID_OK = {1000001, 1000002}
THRESHOLD = 5
WINDOW = 10
BLOCK_SECONDS = 60

recent = defaultdict(deque)
blocked_until = {}


def audit(data):
    data["timestamp"] = datetime.now(timezone.utc).isoformat()
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(data) + "\n")
    print(json.dumps(data), flush=True)


def block_ip(src):
    cmd = [
        "docker", "exec", "-u", "0", GATEWAY,
        "nft", "add", "element", "inet", "ips_response",
        "blocked_v4", "{", str(src), "timeout", f"{BLOCK_SECONDS}s", "}"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if result.returncode:
        audit({
            "decision": "error",
            "action": "block_failed",
            "src_ip": str(src),
            "error": result.stderr.strip()
        })
        return False

    blocked_until[src] = time.monotonic() + BLOCK_SECONDS
    audit({
        "decision": "blocked",
        "action": "temporary_block",
        "src_ip": str(src),
        "duration_seconds": BLOCK_SECONDS
    })
    return True


def process(event, dry_run):
    if event.get("event_type") != "alert":
        return

    alert = event.get("alert", {})
    if alert.get("signature_id") not in SID_OK:
        return

    try:
        src = ipaddress.ip_address(event["src_ip"])
        dst = ipaddress.ip_address(event["dest_ip"])
    except (KeyError, ValueError):
        audit({"decision": "reject", "reason": "invalid_ip"})
        return

    if src != SRC_OK or dst != DST_OK:
        audit({
            "decision": "reject",
            "reason": "outside_policy",
            "src_ip": str(src),
            "dest_ip": str(dst)
        })
        return

    sid = alert["signature_id"]
    if sid == 1000002 and event.get("dest_port") != 8080:
        return
    now = time.monotonic()
    events = recent[(src, sid)]
    events.append(now)
    while events and now - events[0] > WINDOW:
        events.popleft()

    audit({
        "decision": "observed",
        "src_ip": str(src),
        "signature_id": sid,
        "count_in_window": len(events),
        "threshold": THRESHOLD,
        "window_seconds": WINDOW
    })

    if len(events) < THRESHOLD:
        return
    if blocked_until.get(src, 0) > now:
        return

    events.clear()
    if dry_run:
        audit({
            "decision": "dry-run",
            "action": "would_block_source",
            "src_ip": str(src),
            "duration_seconds": BLOCK_SECONDS
        })
    else:
        block_ip(src)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not EVE.exists():
        raise SystemExit(f"EVE non trovato: {EVE}")

    if not args.dry_run:
        check = subprocess.run(
            ["docker", "exec", "-u", "0", GATEWAY,
             "nft", "list", "set", "inet", "ips_response", "blocked_v4"],
            capture_output=True, text=True, timeout=10
        )
        if check.returncode:
            raise SystemExit("Set nftables blocked_v4 non disponibile.")

    print(
        f"Responder {'DRY-RUN' if args.dry_run else 'IPS ATTIVO'}; "
        f"soglia {THRESHOLD}/{WINDOW}s, blocco {BLOCK_SECONDS}s.",
        flush=True
    )

    with EVE.open(encoding="utf-8") as f:
        if not args.from_start:
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
