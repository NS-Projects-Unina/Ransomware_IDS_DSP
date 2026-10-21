#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."

echo "[1/4] Avvio dei container..."
docker-compose up -d

ATTACKER="ransomware_ids_honeypot-Attacker-1"
GATEWAY="ransomware_ids_honeypot-Gateaway-1"
TARGET="ransomware_ids_honeypot-Target-1"

echo "[2/4] Configurazione delle rotte..."
ATTACKER_PID=$(docker inspect -f '{{.State.Pid}}' "$ATTACKER")
TARGET_PID=$(docker inspect -f '{{.State.Pid}}' "$TARGET")

sudo nsenter -t "$ATTACKER_PID" -n \
  ip route replace 10.20.20.0/24 via 10.10.10.3

sudo nsenter -t "$TARGET_PID" -n \
  ip route replace 10.10.10.0/24 via 10.20.20.3

echo "[3/4] Configurazione del firewall..."
# ip_forward è già attivo nel Gateway; non scrivere in /proc/sys.
# Elimina soltanto la tabella del laboratorio, se esiste.
docker exec -u 0 "$GATEWAY" sh -c \
  'nft list table inet lab_filter >/dev/null 2>&1 && nft delete table inet lab_filter || true'

docker exec -u 0 "$GATEWAY" nft add table inet lab_filter

docker exec -u 0 "$GATEWAY" \
  nft 'add chain inet lab_filter forward { type filter hook forward priority 0; policy drop; }'

docker exec -u 0 "$GATEWAY" \
  nft add rule inet lab_filter forward ct state established,related accept

docker exec -u 0 "$GATEWAY" \
  nft add rule inet lab_filter forward \
  ip saddr 10.10.10.0/24 ip daddr 10.20.20.0/24 accept

echo "[4/4] Verifica della connettività..."
docker exec "$ATTACKER" ping -c 2 -W 2 10.10.10.3
docker exec "$ATTACKER" ping -c 3 -W 2 10.20.20.2

echo
echo "Configurazione del laboratorio completata."
echo "Rotte e firewall configurati; controllare gli esiti dei ping sopra."
