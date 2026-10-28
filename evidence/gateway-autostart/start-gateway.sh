#!/bin/sh
set -eu

SURICATA_PID_FILE=/tmp/suricata-lab.pid
ENGINE_PID=""

stop_services() {
    echo "[Gateway] Arresto servizi..."

    if [ -n "$ENGINE_PID" ]; then
        kill "$ENGINE_PID" 2>/dev/null || true
        wait "$ENGINE_PID" 2>/dev/null || true
    fi

    if [ -f "$SURICATA_PID_FILE" ]; then
        kill "$(cat "$SURICATA_PID_FILE")" 2>/dev/null || true
    fi
}

trap 'exit 0' TERM INT
trap 'stop_services' EXIT

echo "[Gateway] Avvio Suricata..."
rm -f "$SURICATA_PID_FILE"

suricata -D \
    -c /etc/suricata/suricata.yaml \
    -i eth1 \
    -S /etc/suricata/rules/local.rules \
    --pidfile "$SURICATA_PID_FILE"

echo "[Gateway] Attesa inizializzazione nftables..."

while ! nft list set ip lab_redirect suspicious_v4 >/dev/null 2>&1; do
    sleep 1
done

echo "[Gateway] Avvio Behavioral Engine APPLY..."

cd /opt/lab
python3 -u -B behavioral-engine.py --apply --poll 0.2 &
ENGINE_PID=$!

echo "[Gateway] Behavioral Engine PID=$ENGINE_PID"

while true; do
    if ! kill -0 "$ENGINE_PID" 2>/dev/null; then
        echo "[Gateway] ERRORE: Behavioral Engine terminato"
        exit 1
    fi

    if [ ! -s "$SURICATA_PID_FILE" ] ||
       ! kill -0 "$(cat "$SURICATA_PID_FILE" 2>/dev/null)" 2>/dev/null; then
        echo "[Gateway] ERRORE: Suricata non operativo"
        exit 1
    fi

    sleep 2 &
    wait $!
done
