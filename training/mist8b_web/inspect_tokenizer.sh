#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
python - "$work/models/MiST-8B/tokenizer_config.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]))
print(json.dumps(p,ensure_ascii=False,indent=2))
PY
"$work/env312/bin/python" - <<'PY'
import importlib.metadata as m
for name in ['transformers','llamafactory','trl','peft','tokenizers']:
 print(name,m.version(name))
PY
