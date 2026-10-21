# Ransomware IDS Honeypot

Laboratorio containerizzato basato su Docker Security Playground.

## Componenti

- Attacker: genera traffico di test.
- Gateaway: instrada il traffico e ospita Suricata e nftables.
- Target: esegue un honeypot TCP personalizzato.

## Architettura

Le reti Docker sono separate:

- internal_net: 10.10.10.0/24
- service_net: 10.20.20.0/24

L'Attacker (10.10.10.2) raggiunge il Target (10.20.20.2)
attraverso il Gateway.

## Honeypot

Il servizio Python ascolta sulla porta TCP 8080.
Registra timestamp, IP sorgente, porta sorgente e porta destinazione.

Log: logs/honeypot/honeypot.jsonl

L'honeypot non esegue comandi ricevuti dalle connessioni.

## IDS

Suricata utilizza le firme in rules/local.rules:

- SID 1000001: traffico ICMP dall'Attacker al Target.
- SID 1000002: connessioni TCP verso l'honeypot.

## IPS

Lo script scripts/ips-response.py analizza gli alert Suricata.

Politica attuale:
- 5 alert dello stesso tipo entro 10 secondi;
- blocco dell'IP sorgente per 60 secondi;
- blocco tramite set nftables blocked_v4.

Il responder supporta la modalità --dry-run.

## Avvio

Dalla directory del progetto:

1. Eseguire docker-compose build.
2. Eseguire ./scripts/start-lab.sh.
3. Verificare la presenza della tabella nftables ips_response.
4. Avviare python3 scripts/ips-response.py.

## Stato del progetto

Funzionanti e verificati:
- Routing tra reti Docker.
- Honeypot TCP.
- Rilevamento IDS tramite Suricata.
- Blocco IPS temporaneo e sblocco automatico.

Da completare:
- Inizializzazione automatica della tabella IPS.
- Simulatore ransomware limitato a file di test.
- Test integrati e documentazione finale.
