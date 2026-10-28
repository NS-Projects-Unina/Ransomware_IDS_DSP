#!/usr/bin/env python3

import json
import os
import socket
from datetime import datetime, timezone

HOST = "0.0.0.0"
PORT = 8080
LOG_FILE = "/app/logs/honeypot.jsonl"

MAX_REQUEST_BYTES = 1024
SOCKET_TIMEOUT = 2

BANNER = (
    b"DOCUMENT-SERVICE/1.0\n"
    b"Internal Document Management Gateway\n"
    b"Commands: LIST, STATUS, GET <document>, SIMULATE_ENCRYPT <document>\n"
)

DOCUMENTS = (
    "budget_2026.xlsx",
    "clienti_2026.csv",
    "contratti_2026.pdf"
)



DECOY_DIR = "/app/decoy-documents"


def simulate_encrypt(document):
    if document not in DOCUMENTS:
        return "ERROR: DOCUMENT NOT ALLOWED\n", "rejected"

    original = os.path.join(DECOY_DIR, document)
    simulated = original + ".simulated"

    if not os.path.isfile(original):
        return "ERROR: DOCUMENT NOT FOUND\n", "not_found"

    try:
        with open(simulated, "x", encoding="utf-8") as handle:
            handle.write(
                "SIMULATED RANSOMWARE ACTIVITY\n"
                f"Original document: {document}\n"
                "No encryption performed.\n"
            )
    except FileExistsError:
        return "SIMULATION ALREADY EXISTS\n", "already_exists"
    except OSError:
        return "ERROR: SIMULATION FAILED\n", "error"

    return "SIMULATION CREATED\n", "created"



def write_event(event):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(json.dumps(event, ensure_ascii=False), flush=True)


def handle_client(client, address):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "connection",
        "src_ip": address[0],
        "src_port": address[1],
        "dest_port": PORT,
        "service": "document_service",
        "request": "",
        "request_bytes": 0
    }

    with client:
        client.settimeout(SOCKET_TIMEOUT)

        try:
            client.sendall(BANNER)

            data = client.recv(MAX_REQUEST_BYTES)

            event["request_bytes"] = len(data)
            event["request"] = data.decode(
                "utf-8", errors="replace"
            ).strip()

            command = event["request"].upper()

            if command == "LIST":
                response = (
                    "AVAILABLE DOCUMENTS\n"
                    + "\n".join(DOCUMENTS)
                    + "\n"
                )

            elif command == "STATUS":
                response = "DOCUMENT SERVICE ONLINE\n"

            elif command.startswith("GET "):
                response = (
                    "ERROR: DOCUMENT ACCESS REQUIRES AUTHORIZATION\n"
                )

            elif command.startswith("SIMULATE_ENCRYPT "):
                document = event["request"][len("SIMULATE_ENCRYPT "):].strip()
                response, outcome = simulate_encrypt(document)
                event["simulation_document"] = document
                event["simulation_outcome"] = outcome

            elif command:
                response = "ERROR: UNKNOWN COMMAND\n"

            else:
                response = "READY\n"

            client.sendall(response.encode("utf-8"))

        except socket.timeout:
            event["error"] = "socket_timeout"

        except OSError as exc:
            event["error"] = type(exc).__name__

        finally:
            write_event(event)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(10)

        print(
            f"Document honeypot listening on {HOST}:{PORT}",
            flush=True
        )

        while True:
            client, address = server.accept()
            handle_client(client, address)


if __name__ == "__main__":
    main()
