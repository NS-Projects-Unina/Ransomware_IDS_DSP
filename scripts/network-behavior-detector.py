#!/usr/bin/env python3
import argparse
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path


def timestamp(event):
    return datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')).timestamp()


def load(path):
    if not path.exists():
        return []
    events = []
    for line in path.open(encoding='utf-8'):
        try:
            e = json.loads(line)
            t = timestamp(e)
            ip = str(ip_address(e['src_ip']))
            if e.get('event_type') not in ('connection', 'legitimate_connection') or not isinstance(e.get('request'), str):
                continue
            if not e['request'].strip():
                continue
            events.append((t, ip, e))
        except (ValueError, KeyError, TypeError):
            continue
    return events


def analyze(events, window, threshold):
    queues = defaultdict(deque)
    last_alert = {}
    for t, ip, e in sorted(events, key=lambda x: x[0]):
        q = queues[ip]
        q.append((t, e))
        while q and t - q[0][0] > window:
            q.popleft()
        commands = [x['request'].strip() for _, x in q]
        documents = {x.split(None, 1)[1] for x in commands if x.upper().startswith('GET ') and len(x.split(None, 1)) == 2}
        # GET requests are denied by the existing honeypot; count attempts, not successful file access.
        request_count = len(commands)
        get_attempts = sum(x.upper().startswith('GET ') for x in commands)
        score = (40 if request_count >= 10 else 0) + (35 if get_attempts >= 5 else 0) + (25 if len(documents) >= 3 else 0)
        if score < threshold or t - last_alert.get(ip, float('-inf')) < window:
            continue
        last_alert[ip] = t
        yield {
            'timestamp': datetime.fromtimestamp(t, timezone.utc).isoformat(),
            'event_type': 'network_behavioral_alert', 'src_ip': ip,
            'score': score, 'window_seconds': window,
            'counts': {'requests': request_count, 'get_attempts': get_attempts, 'distinct_get_documents': len(documents)},
            'attribution': 'application_log_src_ip', 'response': 'alert_only',
            'note': 'GET is denied; request attempts do not imply document access. No filesystem attribution.'
        }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--legitimate', default='logs/honeypot/legitimate.jsonl')
    p.add_argument('--honeypot', default='logs/honeypot/honeypot.jsonl')
    p.add_argument('--output', default='logs/network-behavioral-alerts.jsonl')
    p.add_argument('--window', type=float, default=10)
    p.add_argument('--threshold', type=int, default=70)
    args = p.parse_args()
    if args.window <= 0 or args.threshold <= 0:
        p.error('window and threshold must be positive')
    events = load(Path(args.legitimate)) + load(Path(args.honeypot))
    alerts = list(analyze(events, args.window, args.threshold))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('w', encoding='utf-8') as f:
        for alert in alerts:
            line = json.dumps(alert, ensure_ascii=False)
            f.write(line + '\n')
            print(line)
    print(f'Analyzed {len(events)} application requests; alerts: {len(alerts)}')


if __name__ == '__main__':
    main()
