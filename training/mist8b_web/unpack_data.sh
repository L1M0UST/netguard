#!/usr/bin/env bash
set -euo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
python - <<'PY'
import hashlib, zipfile
from pathlib import Path
p=Path('mist8b-web-train-dev-v3.zip')
expected='5eab920c5a9eeb48f3ccdb1cd05c41ed78b21a2452cd6e6441261de8abf4def0'
assert hashlib.sha256(p.read_bytes()).hexdigest()==expected
with zipfile.ZipFile(p) as z:
 assert z.testzip() is None
 names=set(z.namelist())
 allowed={'data/web/train.jsonl','data/web/dev.jsonl','data/web/dev_full.jsonl','data/web/dataset_info.json','reports/data_report.json'}
 assert names==allowed
 assert not any(Path(name).exists() for name in names)
 z.extractall('.')
print('train/dev archive verified and extracted; sealed test absent')
PY
wc -l data/web/train.jsonl data/web/dev.jsonl data/web/dev_full.jsonl
