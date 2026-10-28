# Ransomware IDS & Honeypot

Questo progetto nasce come laboratorio di Network Security per studiare come rilevare attività sospette all'interno di una rete e applicare contromisure automatiche.

L'ambiente è stato realizzato con Docker e comprende un sistema IDS/IPS basato su Suricata, un motore di analisi comportamentale scritto in Python, un honeypot e un componente per il monitoraggio dei file.

Le attività vengono simulate in una rete isolata, utilizzando servizi e documenti di test.

## Struttura del laboratorio

Il laboratorio utilizza quattro container:

 **Attacker**, da cui viene generato il traffico di prova.
 **Gateaway**, che collega le due reti e ospita Suricata, nftables e il Behavioral Engine.
 **Target**, che espone il servizio legittimo e l'honeypot.
 **FileMonitor**, utilizzato per osservare le operazioni sul filesystem.

La rete è suddivisa in due sottoreti Docker:

| Rete | Indirizzamento |
|---|---|
| `internal_net` | `10.10.10.0/24` |
| `service_net` | `10.20.20.0/24` |

L'Attacker ha indirizzo `10.10.10.2`, mentre il Target utilizza `10.20.20.2`. Il Gateway è collegato a entrambe le reti tramite gli indirizzi `10.10.10.3` e `10.20.20.3`.

Il nome `Gateaway` è mantenuto nella configurazione per compatibilità con gli script del progetto.

## Rilevamento e risposta

Suricata analizza il traffico che attraversa il Gateway. Le regole personalizzate si trovano nella directory `rules/` e comprendono firme per riconoscere richieste applicative e payload utilizzati nelle simulazioni.

Accanto al rilevamento basato su firme è presente un Behavioral Engine, sviluppato per individuare sequenze anomale di richieste. La versione V2 utilizza due finestre temporali, una di 10 secondi (`fast_10s`) e una di 60 secondi (`extended_60s`).

Quando viene rilevata una sequenza che soddisfa i criteri previsti, il motore può aggiungere l'indirizzo IP sorgente al set nftables `suspicious_v4`.

Questo permette di reindirizzare temporaneamente il traffico diretto al servizio legittimo sulla porta TCP 8081 verso l'honeypot sulla porta 8080. La durata della regola è di 60 secondi.

Il progetto comprende anche un meccanismo IPS separato, basato sul set `blocked_v4`, per il blocco temporaneo degli indirizzi sorgente.

## Honeypot e monitoraggio dei file

Sul Target sono presenti due servizi TCP:

 Porta **8081**: servizio legittimo.
 Porta **8080**: honeypot che simula un servizio documentale.

L'honeypot registra le connessioni e restituisce risposte controllate, senza eseguire comandi inviati dai client.

Il FileMonitor osserva invece le operazioni sul filesystem. Gli eventi raccolti possono essere confrontati con quelli di rete attraverso uno script di correlazione offline.

Questa correlazione viene utilizzata come supporto all'analisi: la vicinanza temporale tra eventi non dimostra necessariamente che abbiano la stessa causa.

## Requisiti e avvio

Il laboratorio è stato sviluppato e verificato su Kali Linux. Per eseguirlo sono necessari Docker, Docker Compose, Python 3, `sudo` e `nsenter`.

Dalla directory principale del progetto:

```bash
docker volume create ransomware_demo_data
mkdir -p logs/suricata logs/honeypot
docker-compose build
./scripts/start-lab.sh
```

Il volume `ransomware_demo_data` deve esistere prima dell'avvio perché è dichiarato come volume esterno in Docker Compose. Viene utilizzato dal Target per i documenti di test.

Lo script `start-lab.sh` avvia i container, configura le rotte e inizializza le tabelle nftables necessarie.

Suricata e il Behavioral Engine vengono avviati automaticamente all'interno del Gateway tramite `gateway/start-gateway.sh`.

Per controllare lo stato dei container:

```bash
docker-compose ps
```

## Test effettuati

Durante lo sviluppo sono stati verificati il routing tra le reti, il funzionamento dei due servizi TCP, il rilevamento tramite Suricata e il monitoraggio del filesystem.

Un test integrato ha permesso di verificare anche la risposta automatica del Behavioral Engine V2. Dopo una sequenza di richieste `GET`, il motore ha rilevato un comportamento `fast_10s` con punteggio 100 e ha inserito l'indirizzo dell'Attacker nel set di reindirizzamento.

Le richieste successive verso la porta 8081 hanno raggiunto l'honeypot. Trascorso il timeout di 60 secondi, il servizio legittimo è tornato accessibile.

Sono stati inoltre effettuati test offline sul rilevamento comportamentale e sulla correlazione degli eventi.

## Limiti del progetto

Le prove sono state eseguite in un ambiente controllato, con traffico e comportamenti simulati. I risultati mostrano il funzionamento dei meccanismi implementati, ma non rappresentano una valutazione su attacchi ransomware reali.

In particolare, il rilevamento di richieste sospette non costituisce una prova di cifratura dei file, così come la correlazione degli eventi non dimostra da sola un rapporto causale.

Il laboratorio è destinato esclusivamente a scopi didattici.
