#!/bin/sh
set -eu

TARGET_IP="10.20.20.2"
TARGET_PORT="8080"
WORKDIR="/tmp/ransomware-lab-demo"
EVENTS=5

echo "[1/3] Preparazione dei file dimostrativi..."

mkdir -p "$WORKDIR"

printf 'Documento dimostrativo A\n' > "$WORKDIR/documento-a.txt"
printf 'Documento dimostrativo B\n' > "$WORKDIR/documento-b.txt"
printf 'Documento dimostrativo C\n' > "$WORKDIR/documento-c.txt"

echo "[2/3] Simulazione dell'impatto sui file..."

for file in "$WORKDIR"/*.txt; do
    cp "$file" "$file.simulated"
done

echo "File originali preservati."
echo "Copie dimostrative create:"
ls -l "$WORKDIR"

echo "[3/3] Generazione del traffico verso l'honeypot..."

i=1
while [ "$i" -le "$EVENTS" ]; do
    echo "Connessione $i/$EVENTS"

    printf 'LAB_SIMULATION event=%s\n' "$i" |
        nc -w 1 "$TARGET_IP" "$TARGET_PORT" || true

    i=$((i + 1))
    sleep 1
done

echo "Simulazione completata."
