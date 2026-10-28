#!/bin/sh
set -eu

ATTACKER="ransomware_ids_honeypot-Attacker-1"
TARGET_IP="10.20.20.2"
TARGET_PORT="8081"

send_request() {
    request="$1"

    docker exec "$ATTACKER" \
        sh -c 'printf "%s\n" "$1" | nc -w 3 "$2" "$3"' \
        sh "$request" "$TARGET_IP" "$TARGET_PORT"
}

echo "Avvio simulazione"
echo "Modalità: simulazione senza cifratura"

echo
echo "[1/3] Connessione al servizio sulla porta 8081"
response=$(send_request "STATUS")
printf '%s\n' "$response"

printf '%s\n' "$response" | grep -q 'LAB_LEGITIMATE_SERVICE' || {
    echo "Errore: risposta inattesa dal servizio legittimo"
    exit 1
}

echo
echo "[2/3] Invio della richiesta di test"
response=$(send_request "SIMULATE_ENCRYPT budget_2026.xlsx" || true)

if [ -n "$response" ]; then
    printf '%s\n' "$response"
else
    echo "Comando bloccato o senza risposta: comportamento atteso dall'IPS."
fi

sleep 2

echo
echo "[3/3] Verifica della deviazione verso la porta 8080"
response=$(send_request "LIST")
printf '%s\n' "$response"

printf '%s\n' "$response" | grep -q 'DOCUMENT-SERVICE/1.0' || {
    echo "Errore: honeypot non raggiunto tramite la porta 8081"
    exit 1
}

echo
echo "Simulazione completata: deviazione del traffico verificata."
