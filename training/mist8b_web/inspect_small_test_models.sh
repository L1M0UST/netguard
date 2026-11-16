#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
find "$work/models" -maxdepth 3 -name config.json -type f -printf '%p\n' | while read -r path; do
 "$work/env312/bin/python" - "$path" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);x=json.loads(p.read_text())
print(p.parent.name, x.get('model_type'),x.get('architectures'),x.get('hidden_size'),x.get('num_hidden_layers'))
PY
done
