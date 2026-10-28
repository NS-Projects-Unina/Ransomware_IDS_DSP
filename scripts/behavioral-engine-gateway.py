#!/usr/bin/env python3
import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import subprocess
import time
import uuid

SOURCES = [Path('logs/honeypot/legitimate.jsonl'), Path('logs/honeypot/honeypot.jsonl')]
ALERTS = Path('logs/network-behavioral-live-alerts.jsonl')
AUDIT = Path('logs/behavioral-live-response.jsonl')
GATEWAY = 'ransomware_ids_honeypot-Gateaway-1'
ALLOWED = ipaddress.ip_address('10.10.10.2')
WINDOW = 10.0
LONG_WINDOW = 60.0
LONG_GET_THRESHOLD = 12
LONG_DOCUMENT_THRESHOLD = 3
COOLDOWN = 60.0
MAX_AGE = 30.0


def emit(path, item):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(item, ensure_ascii=False) + '\n')
    print(json.dumps(item, ensure_ascii=False), flush=True)


def parse_time(value):
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timestamp without timezone')
    return dt.timestamp()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--apply', action='store_true', help='Enable nftables action (default: dry-run)')
    p.add_argument('--poll', type=float, default=0.2)
    args = p.parse_args()
    if args.poll <= 0:
        p.error('--poll must be positive')

    # Begin at EOF: never process historical requests on service startup.
    offsets = {path: path.stat().st_size if path.exists() else 0 for path in SOURCES}
    buffers = defaultdict(deque)
    cooldown_until = defaultdict(float)
    print('Behavioral engine started: ' + ('APPLY' if args.apply else 'DRY-RUN') + '; following new log entries only', flush=True)
    try:
        while True:
            now = time.time()
            for path in SOURCES:
                if not path.exists():
                    continue
                size = path.stat().st_size
                if size < offsets[path]:
                    offsets[path] = 0
                with path.open('rb') as f:
                    f.seek(offsets[path])
                    while True:
                        line = f.readline()
                        if not line:
                            break
                        if not line.endswith(b'\n'):
                            break  # wait for a complete JSONL record
                        offsets[path] = f.tell()
                        try:
                            event = json.loads(line)
                            ts = parse_time(event['timestamp'])
                            src = ipaddress.ip_address(event['src_ip'])
                        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
                            continue
                        if src != ALLOWED or not (0 <= now - ts <= MAX_AGE):
                            continue
                        request = event.get('request', '')
                        if not isinstance(request, str):
                            continue
                        tokens = request.strip().split(maxsplit=1)
                        is_get = bool(tokens and tokens[0].upper() == 'GET')
                        doc = tokens[1].strip() if is_get and len(tokens) == 2 else None
                        q = buffers[str(src)]
                        q.append((ts, is_get, doc))
                        cutoff = ts - LONG_WINDOW
                        while q and q[0][0] < cutoff:
                            q.popleft()
                        # The log sources may be read out of order; avoid false counts.
                        if any(q[i][0] > q[i + 1][0] for i in range(len(q) - 1)):
                            q = deque(sorted(q, key=lambda x: x[0]))
                            buffers[str(src)] = q
                        recent = [x for x in q if ts - WINDOW <= x[0] <= ts]
                        extended = [x for x in q if ts - LONG_WINDOW <= x[0] <= ts]
                        requests = len(recent)
                        gets = sum(x[1] for x in recent)
                        documents = len({x[2] for x in recent if x[2]})
                        score = (40 if requests >= 10 else 0) + (35 if gets >= 5 else 0) + (25 if documents >= 3 else 0)
                        long_gets = sum(x[1] for x in extended)
                        long_documents = len({x[2] for x in extended if x[1] and x[2]})
                        fast_trigger = score >= 70
                        slow_trigger = long_gets >= LONG_GET_THRESHOLD and long_documents >= LONG_DOCUMENT_THRESHOLD
                        if not (fast_trigger or slow_trigger) or now < cooldown_until[str(src)]:
                            continue
                        detection_mode = 'fast_10s' if fast_trigger else 'extended_60s' 
                        cooldown_until[str(src)] = now + COOLDOWN
                        alert = {
                            'timestamp': datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                            'event_type': 'network_behavioral_alert',
                            'event_id': str(uuid.uuid4()),
                            'src_ip': str(src), 'score': score,
                            'detection_mode': detection_mode,
                            'window_seconds': WINDOW if fast_trigger else LONG_WINDOW,
                            'counts': {'requests': requests if fast_trigger else len(extended),
                                       'get_attempts': gets if fast_trigger else long_gets,
                                       'distinct_get_documents': documents if fast_trigger else long_documents},
                            'attribution': 'application_log_src_ip',
                            'response': 'pending',
                            'note': 'GET attempts do not prove document access; no filesystem attribution. Score uses 10s criteria even for extended trigger.'
                        }
                        emit(ALERTS, alert)
                        action = {'timestamp': datetime.now(timezone.utc).isoformat(),
                                  'event_id': alert['event_id'], 'src_ip': str(src), 'score': score,
                                  'detection_mode': detection_mode,
                                  'duration_seconds': 60}
                        if not args.apply:
                            action['decision'] = 'dry-run'
                            action['action'] = 'would_redirect'
                        else:
                            cmd = ['nft', 'add', 'element',
                                   'ip', 'lab_redirect', 'suspicious_v4', '{', str(src), 'timeout', '60s', '}']
                            try:
                                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                                action['decision'] = 'redirected' if result.returncode == 0 else 'error'
                                if result.returncode:
                                    action['error'] = result.stderr.strip()
                            except (OSError, subprocess.TimeoutExpired) as exc:
                                action['decision'] = 'error'
                                action['error'] = str(exc)
                        emit(AUDIT, action)
            time.sleep(args.poll)
    except KeyboardInterrupt:
        print('Behavioral engine stopped', flush=True)


if __name__ == '__main__':
    main()
