#!/usr/bin/env bash
set -euo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
python - <<'PY'
import hashlib,zipfile
from pathlib import Path
p=Path('pipeline-payload.zip')
assert hashlib.sha256(p.read_bytes()).hexdigest()=='f80680845efac5809f1ca08426d1ac7de4c6d52c208abbf4ee50e087d51d8a67'
allowed={'configs/smoke.yaml','configs/profile.yaml','configs/round1.yaml','run_pipeline.sh'}
with zipfile.ZipFile(p) as z:
 assert z.testzip() is None and set(z.namelist())==allowed
 assert not any(Path(name).exists() for name in allowed)
 z.extractall('.')
print('pipeline payload verified')
PY
