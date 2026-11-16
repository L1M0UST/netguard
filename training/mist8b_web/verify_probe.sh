#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test -f "$work/runs/infra_probe_v2/adapter_config.json"
test -f "$work/runs/infra_probe_v2/adapter_model.safetensors"
"$work/env312/bin/python" - "$work/runs/infra_probe_v2" <<'PY'
import json,sys
from pathlib import Path
from safetensors import safe_open
p=Path(sys.argv[1])
config=json.loads((p/'adapter_config.json').read_text())
assert config['r']==16 and config['peft_type']=='LORA'
with safe_open(p/'adapter_model.safetensors',framework='pt') as f:
 keys=list(f.keys())
 assert keys and any('lora_A' in k for k in keys) and any('lora_B' in k for k in keys)
 print('random model 2-step QLoRA probe adapter tensors',len(keys),'rank',config['r'])
print('RANDOM_MODEL_INFRASTRUCTURE_PROBE_PASSED')
PY
