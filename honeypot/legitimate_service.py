#!/usr/bin/env python3

import json
import os
import socket
from datetime import datetime, timezone

HOST = "0.0.0.0"
PORT = 8081
LOG_FILE = "/app/logs/legitimate.jsonl"


def main():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(10)

        print(f"Legitimate service listening on {HOST}:{PORT}", flush=True)

        while True:
            client, address = server.accept()

            client.settimeout(1.0)

            try:
                request = client.recv(1024).decode("utf-8", errors="replace").strip()
            except (OSError, TimeoutError):
                request = ""

            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "legitimate_connection",
                "src_ip": address[0],
                "src_port": address[1],
                "dest_port": PORT,
                "request": request
            }

            with open(LOG_FILE, "a", encoding="utf-8") as log:
                log.write(json.dumps(event) + "\n")

            print(json.dumps(event), flush=True)

            try:
                client.sendall(b"LAB_LEGITIMATE_SERVICE\n")
            except OSError:
                pass
            finally:
                client.close()


if __name__ == "__main__":
    main()
