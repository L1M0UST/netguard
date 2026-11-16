#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
find "$work/models/probe-random-qwen3-v2" -maxdepth 1 -printf '%f\n' | head -20
find "$work/runs" -maxdepth 3 -name adapter_config.json -print | while read -r f; do
 "$work/env312/bin/python" - "$f" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);x=json.loads(p.read_text())
print(p.parent, 'base',x.get('base_model_name_or_path'),'rank',x.get('r'))
PY
done
nvidia-smi --query-gpu=memory.used,memory.free --format=csv,noheader,nounits
