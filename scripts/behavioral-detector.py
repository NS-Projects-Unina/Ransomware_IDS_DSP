#!/usr/bin/env python3
import argparse
import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


def parse_ts(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def analyze(events, window=10, threshold=70):
    recent = deque()
    last_alert = float('-inf')
    for event in events:
        if event.get('event_type') not in {'file_created', 'file_modified', 'file_deleted', 'file_renamed'}:
            continue
        try:
            ts = parse_ts(event['timestamp'])
        except (KeyError, ValueError, TypeError):
            continue
        recent.append((ts, event))
        while recent and ts - recent[0][0] > window:
            recent.popleft()
        batch = [e for _, e in recent]
        writes = sum(e['event_type'] in ('file_created', 'file_modified') for e in batch)
        renames = sum(e['event_type'] == 'file_renamed' for e in batch)
        deletes = sum(e['event_type'] == 'file_deleted' for e in batch)
        distinct = len({e['path'] for e in batch})
        score = (30 if writes >= 10 else 0) + (35 if renames >= 5 else 0) + (20 if deletes >= 5 else 0) + (25 if distinct >= 10 else 0)
        if score >= threshold and ts - last_alert >= window:
            last_alert = ts
            yield {
                'timestamp': datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                'event_type': 'behavioral_alert', 'source': 'behavioral_detector',
                'score': score, 'window_seconds': window,
                'counts': {'writes': writes, 'renames': renames, 'deletes': deletes, 'distinct_paths': distinct},
                'attribution': 'unattributed', 'response': 'alert_only',
                'note': 'Experimental heuristic, not proof of ransomware',
            }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default='logs/monitor/filesystem.jsonl')
    parser.add_argument('--output', default='logs/behavioral-alerts.jsonl')
    parser.add_argument('--window', type=int, default=10)
    parser.add_argument('--threshold', type=int, default=70)
    args = parser.parse_args()
    if args.window <= 0 or args.threshold <= 0:
        parser.error('window and threshold must be positive')
    source = Path(args.input)
    if not source.exists():
        parser.error(f'missing input: {source}')
    records = []
    for line in source.read_text(encoding='utf-8').splitlines():
        try:
            record = json.loads(line)
            record['_sort_ts'] = parse_ts(record['timestamp'])
            records.append(record)
        except (ValueError, KeyError, TypeError):
            continue
    records.sort(key=lambda e: e['_sort_ts'])
    alerts = list(analyze(records, args.window, args.threshold))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Recalculate the report from the input rather than appending duplicate alerts.
    with output.open('w', encoding='utf-8') as handle:
        for alert in alerts:
            handle.write(json.dumps(alert, ensure_ascii=False) + '\n')
            print(json.dumps(alert, ensure_ascii=False))
    print(f'Analyzed {len(records)} events; alerts: {len(alerts)}')


if __name__ == '__main__':
    main()
