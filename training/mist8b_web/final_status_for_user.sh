#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'time_utc='; date -u +'%F %T UTC'
for key in qwen_round1_now vllm_install qwen_vllm_pipeline qwen_adapter_backup qwen_checkpoint_monitor mist_after_qwen; do
 printf '%s=' "$key"; cat "$work/reports/${key}_state.txt" 2>/dev/null || echo unavailable
done
"$work/env312/bin/python" - "$work" <<'PY'
import json,sys
from pathlib import Path
w=Path(sys.argv[1]);p=w/'runs/qwen3_round1/trainer_log.jsonl'
if p.exists():
 rows=[]
 for line in p.read_text().splitlines():
  try:rows.append(json.loads(line))
  except json.JSONDecodeError:pass
 if rows:
  x=rows[-1]
  print('last_training_log', {k:x.get(k) for k in ('current_steps','total_steps','loss','eval_loss','elapsed_time','remaining_time') if k in x})
p=w/'reports/qwen_preserved_checkpoints.json'
if p.exists():
 x=json.loads(p.read_text());print('qwen_preserved_steps',[i['step'] for i in x['candidates']])
PY
printf 'gpu_used_total_mib='; nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader,nounits
df -h / /root/sj-tmp | tail -2
