#!/usr/bin/env python3

import json
import os
import socket
from datetime import datetime, timezone

HOST = "0.0.0.0"
PORT = 8080
LOG_FILE = "/app/logs/honeypot.jsonl"


def record_event(client, address):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "connection",
        "src_ip": address[0],
        "src_port": address[1],
        "dest_port": PORT
    }

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(json.dumps(event) + "\n")

    print(json.dumps(event), flush=True)
    client.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(10)

        print(f"Honeypot listening on {HOST}:{PORT}", flush=True)

        while True:
            client, address = server.accept()
            record_event(client, address)


if __name__ == "__main__":
    main()
