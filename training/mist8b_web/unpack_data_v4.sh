#!/usr/bin/env bash
set -euo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
python - <<'PY'
import hashlib, zipfile
from pathlib import Path
p=Path('mist8b-web-train-dev-v4.zip')
expected='be190213bdbb900836f5922b42be37c21a30befb090b83651900e979f1320499'
assert hashlib.sha256(p.read_bytes()).hexdigest()==expected
with zipfile.ZipFile(p) as z:
 assert z.testzip() is None
 names=set(z.namelist())
 allowed={'data/web_v4/train.jsonl','data/web_v4/dev.jsonl','data/web_v4/dev_full.jsonl','data/web_v4/dataset_info.json','reports/data_report_v4.json'}
 assert names==allowed
 assert not any(Path(name).exists() for name in names)
 z.extractall('.')
print('v4 train/dev archive verified and extracted; sealed test absent')
PY
wc -l data/web_v4/train.jsonl data/web_v4/dev.jsonl data/web_v4/dev_full.jsonl
