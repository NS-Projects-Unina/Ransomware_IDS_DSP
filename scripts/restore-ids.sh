#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."

GATEWAY="ransomware_ids_honeypot-Gateaway-1"

echo "Ripristino modalità IDS"

echo "Rimozione regole NFQUEUE..."
if docker inspect "$GATEWAY" >/dev/null 2>&1 &&
   docker exec "$GATEWAY" nft list table inet lab_nfqueue >/dev/null 2>&1; then
    docker exec "$GATEWAY" nft delete table inet lab_nfqueue
fi

echo "Riavvio Gateway..."
docker-compose up -d --force-recreate --no-deps Gateaway

echo "Ripristino rotte e firewall..."
./scripts/start-lab.sh

echo "Verifica processo Suricata..."
docker exec "$GATEWAY" sh -c '
  found=0
  for p in /proc/[0-9]*/cmdline; do
    cmd=$(tr "\000" " " < "$p" 2>/dev/null) || continue
    case "$cmd" in
      suricata\ *"-i eth1"*)
        printf "%s\n" "$cmd"
        found=1
        ;;
    esac
  done
  [ "$found" -eq 1 ]
'

echo "Ripristino completato."
