#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."

echo "[1/6] Avvio dei container..."
docker-compose up -d

ATTACKER="ransomware_ids_honeypot-Attacker-1"
GATEWAY="ransomware_ids_honeypot-Gateaway-1"
TARGET="ransomware_ids_honeypot-Target-1"

echo "[2/6] Configurazione delle rotte..."
ATTACKER_PID=$(docker inspect -f '{{.State.Pid}}' "$ATTACKER")
TARGET_PID=$(docker inspect -f '{{.State.Pid}}' "$TARGET")

sudo nsenter -t "$ATTACKER_PID" -n \
  ip route replace 10.20.20.0/24 via 10.10.10.3

sudo nsenter -t "$TARGET_PID" -n \
  ip route replace 10.10.10.0/24 via 10.20.20.3

echo "[3/6] Configurazione del firewall..."
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

echo "[4/6] Inizializzazione IPS..."
if docker exec -u 0 "$GATEWAY" nft list table inet ips_response >/dev/null 2>&1; then
  echo "Tabella ips_response già presente: configurazione preservata."
else
  docker exec -i -u 0 "$GATEWAY" nft -f - <<'NFT'
add table inet ips_response
add set inet ips_response blocked_v4 { type ipv4_addr; timeout 1m; }
add chain inet ips_response forward_guard { type filter hook forward priority -10; policy accept; }
add rule inet ips_response forward_guard ip saddr @blocked_v4 ip daddr 10.20.20.0/24 drop
NFT
  echo "Tabella ips_response creata."
fi

echo "[5/6] Inizializzazione reindirizzamento selettivo..."
if docker exec -u 0 "$GATEWAY" nft list table ip lab_redirect >/dev/null 2>&1; then
  echo "Tabella lab_redirect già presente: configurazione preservata."
else
  docker exec -i -u 0 "$GATEWAY" nft -f - <<'NFT'
add table ip lab_redirect
add set ip lab_redirect suspicious_v4 { type ipv4_addr; timeout 1m; }
add chain ip lab_redirect prerouting { type nat hook prerouting priority dstnat; policy accept; }
add rule ip lab_redirect prerouting iifname "eth0" ip saddr @suspicious_v4 ip daddr 10.20.20.2 tcp dport 8081 dnat to 10.20.20.2:8080
NFT
  echo "Tabella lab_redirect creata."
fi

echo "[6/6] Verifica della connettività..."
docker exec "$ATTACKER" ping -c 2 -W 2 10.10.10.3
docker exec "$ATTACKER" ping -c 3 -W 2 10.20.20.2

echo
echo "Configurazione del laboratorio completata."
echo "Rotte e firewall configurati; controllare gli esiti dei ping sopra."
