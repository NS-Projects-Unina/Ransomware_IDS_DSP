#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."

GATEWAY="ransomware_ids_honeypot-Gateaway-1"
ACTIVATION_STARTED=0

rollback() {
    status=$?
    trap - ERR
    echo "Errore durante l'attivazione IPS (codice $status)."
    if [ "$ACTIVATION_STARTED" -eq 1 ]; then
        echo "Tentativo di ripristino IDS..."
        ./scripts/restore-ids.sh || echo "Ripristino automatico non riuscito."
    fi
    exit "$status"
}

trap rollback ERR

echo "Attivazione modalità IPS inline"

echo "Verifica modalità corrente..."
if docker exec "$GATEWAY" nft list table inet lab_nfqueue >/dev/null 2>&1; then
    echo "Tabella NFQUEUE già presente: attivazione interrotta." >&2
    exit 1
fi

echo "Verifica regole IPS..."
docker exec "$GATEWAY" \
  suricata -T \
  -c /etc/suricata/suricata.yaml \
  -S /etc/suricata/rules/inline.rules

ACTIVATION_STARTED=1

echo "Arresto istanza IDS..."
docker exec "$GATEWAY" sh -c '
  for p in /proc/[0-9]*/cmdline; do
    cmd=$(tr "\000" " " < "$p" 2>/dev/null) || continue
    case "$cmd" in
      suricata\ *"-i eth1"*)
        pid=${p#/proc/}
        pid=${pid%/cmdline}
        kill -TERM "$pid"
        ;;
    esac
  done
'

echo "Attesa terminazione IDS..."
docker exec "$GATEWAY" sh -c '
  attempt=0
  while [ "$attempt" -lt 10 ]; do
    found=0
    for p in /proc/[0-9]*/cmdline; do
      cmd=$(tr "\000" " " < "$p" 2>/dev/null) || continue
      case "$cmd" in
        suricata\ *"-i eth1"*) found=1 ;;
      esac
    done
    [ "$found" -eq 0 ] && exit 0
    attempt=$((attempt + 1))
    sleep 1
  done
  echo "Processo IDS ancora attivo" >&2
  exit 1
'

echo "Avvio Suricata con NFQUEUE..."
docker exec "$GATEWAY" \
  suricata -D \
  -c /etc/suricata/suricata.yaml \
  -q 0 \
  -S /etc/suricata/rules/inline.rules \
  --pidfile /tmp/suricata-inline.pid

sleep 3

echo "Verifica processo IPS..."
docker exec "$GATEWAY" sh -c '
  found=0
  for p in /proc/[0-9]*/cmdline; do
    cmd=$(tr "\000" " " < "$p" 2>/dev/null) || continue
    case "$cmd" in
      suricata\ *"-q 0"*)
        printf "%s\n" "$cmd"
        found=1
        ;;
    esac
  done
  [ "$found" -eq 1 ]
'

echo "Verifica registrazione coda NFQUEUE 0..."
docker exec "$GATEWAY" sh -c '
  attempt=0
  while [ "$attempt" -lt 10 ]; do
    process_found=0
    for p in /proc/[0-9]*/cmdline; do
      cmd=$(tr "\000" " " < "$p" 2>/dev/null) || continue
      case "$cmd" in
        suricata\ *"-q 0"*) process_found=1 ;;
      esac
    done
    if [ "$process_found" -eq 1 ] &&
       [ -r /proc/net/netfilter/nfnetlink_queue ] &&
       awk '\''$1 == 0 { found=1 } END { exit !found }'\'' /proc/net/netfilter/nfnetlink_queue; then
      echo "Coda NFQUEUE 0 registrata"
      exit 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  echo "Coda NFQUEUE 0 non registrata" >&2
  exit 1
'

echo "Configurazione NFQUEUE..."
docker exec -i "$GATEWAY" nft -f - <<'NFT'
add table inet lab_nfqueue
add chain inet lab_nfqueue forward { type filter hook forward priority -20; policy accept; }
add rule inet lab_nfqueue forward iifname "eth1" ip saddr 10.10.10.2 ip daddr 10.20.20.2 tcp dport 8081 queue num 0 bypass
add rule inet lab_nfqueue forward iifname "eth0" ip saddr 10.20.20.2 ip daddr 10.10.10.2 tcp sport 8081 queue num 0 bypass
NFT

echo "Modalità IPS inline attiva."
