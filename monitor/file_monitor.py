#!/usr/bin/env python3
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

WATCH_DIR = Path('/data')
LOG_FILE = Path('/logs/filesystem.jsonl')
POLL_INTERVAL = 0.5


def snapshot():
    result = {}
    for root, _, files in os.walk(WATCH_DIR):
        for filename in files:
            path = Path(root) / filename
            try:
                stat = path.stat()
            except (FileNotFoundError, PermissionError):
                continue
            result[str(path.relative_to(WATCH_DIR))] = {
                'size': stat.st_size, 'mtime_ns': stat.st_mtime_ns,
                'inode': stat.st_ino, 'device': stat.st_dev,
            }
    return result


def emit(kind, path, current=None, previous=None, old_path=None):
    event = {
        'event_id': str(uuid.uuid4()),
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event_type': kind, 'path': path, 'source': 'filesystem_monitor',
    }
    if current is not None:
        event['size'] = current['size']
    if previous is not None:
        event['previous_size'] = previous['size']
    if old_path is not None:
        event['old_path'] = old_path
    line = json.dumps(event, ensure_ascii=False)
    with LOG_FILE.open('a', encoding='utf-8') as handle:
        handle.write(line + '\n')
    print(line, flush=True)


def compare(previous, current):
    deleted = set(previous) - set(current)
    created = set(current) - set(previous)
    # Inode matching is reliable for rename only when unique on the same device.
    by_old = {}
    by_new = {}
    for path in deleted:
        key = (previous[path]['device'], previous[path]['inode'])
        by_old.setdefault(key, []).append(path)
    for path in created:
        key = (current[path]['device'], current[path]['inode'])
        by_new.setdefault(key, []).append(path)
    for key in sorted(set(by_old) & set(by_new)):
        if len(by_old[key]) == 1 and len(by_new[key]) == 1:
            old, new = by_old[key][0], by_new[key][0]
            emit('file_renamed', new, current[new], previous[old], old)
            deleted.remove(old)
            created.remove(new)
    for path in sorted(created):
        emit('file_created', path, current[path])
    for path in sorted(set(previous) & set(current)):
        if previous[path] != current[path]:
            emit('file_modified', path, current[path], previous[path])
    for path in sorted(deleted):
        emit('file_deleted', path, previous=previous[path])


def main():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    previous = snapshot()
    print(f'FileMonitor started: {WATCH_DIR}, files={len(previous)}', flush=True)
    while True:
        time.sleep(POLL_INTERVAL)
        current = snapshot()
        compare(previous, current)
        previous = current


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
