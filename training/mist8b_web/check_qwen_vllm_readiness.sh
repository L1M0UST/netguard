#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
"$work/env312/bin/python" - "$work" <<'PY'
import json,sys
from pathlib import Path
w=Path(sys.argv[1])
for name in ['reports/qwen3_download.json','reports/qwen_token_audit.json','reports/data_report_v4.json',
             'reports/environment312-verified-freeze.txt','reports/vllm_environment_freeze.txt',
             'data/web_fit_v2/dev.jsonl','evaluate_web.py','evaluate_qwen_vllm.py',
             'compare_qwen_vllm.py','export_qwen_vllm.py','export_qwen_adapter.py']:
 p=w/name
 assert p.is_file() and p.stat().st_size>0, name
print('required current evaluation and export inputs exist')
tiny=json.loads((w/'runs/infra_probe_v2/adapter_config.json').read_text())
smoke=json.loads((w/'runs/qwen3_smoke/adapter_config.json').read_text())
for key in ['peft_type','r','lora_alpha','target_modules','bias']:
 print(key, 'tiny',tiny.get(key),'qwen_smoke',smoke.get(key))
 if key=='target_modules':
  assert set(tiny.get(key))==set(smoke.get(key)),key
 else:
  assert tiny.get(key)==smoke.get(key),key
print('tiny and real Qwen smoke adapter configurations agree for main LoRA parameters')
PY
