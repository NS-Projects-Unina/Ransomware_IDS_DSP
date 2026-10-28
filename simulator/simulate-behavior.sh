#!/bin/sh
set -eu
# Runs only inside the isolated Target container; never touches original decoys.
TARGET="${TARGET_CONTAINER:-ransomware_ids_honeypot-Target-1}"
# docker exec requires stdin for the Python script.
docker exec -i "$TARGET" python3 - <<'PY'
from pathlib import Path
import time
import uuid
root = Path('/app/decoy-documents/behavioral-lab') / ('run-' + uuid.uuid4().hex[:10])
root.mkdir(parents=True, exist_ok=False)
print('Simulation directory:', root, flush=True)
for i in range(15):
    p = root / f'item-{i:02d}.txt'
    p.write_text(f'Synthetic test file {i}\n', encoding='utf-8')
time.sleep(1.2)  # Allow polling monitor to observe creations.
for i in range(15):
    p = root / f'item-{i:02d}.txt'
    p.rename(root / f'item-{i:02d}.renamed')
time.sleep(1.2)
print('Safe simulation completed. Files left for inspection.', flush=True)
PY
