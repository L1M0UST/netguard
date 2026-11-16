#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'utc_time='; date -u +'%F %T'
for key in qwen_round1_now qwen_vllm_pipeline qwen_adapter_backup qwen_checkpoint_monitor mist_after_qwen mist_checkpoint_monitor; do
  printf '%s_state=' "$key"; cat "$work/reports/${key}_state.txt" 2>/dev/null || echo unavailable
  if [ -f "$work/$key.pid" ]; then
    pid=$(cat "$work/$key.pid")
    ps -p "$pid" -o pid=,stat=,args= | cut -c1-120 || true
  fi
done
"$work/env312/bin/python" - "$work" <<'PY'
import json,sys
from pathlib import Path
w=Path(sys.argv[1])
for model in ('qwen3_round1','round1'):
 p=w/'runs'/model/'trainer_log.jsonl'
 if p.exists():
  lines=[]
  for s in p.read_text(encoding='utf-8').splitlines():
   try:lines.append(json.loads(s))
   except json.JSONDecodeError:pass
  if lines:
   row=lines[-1]
   print(model+'_latest',json.dumps({k:row[k] for k in ('current_steps','total_steps','loss','eval_loss','elapsed_time','remaining_time') if k in row},ensure_ascii=False))
for name in ('qwen','mist'):
 p=w/'reports'/f'{name}_preserved_checkpoints.json'
 if p.exists():
  x=json.loads(p.read_text())
  print(name+'_preserved',[(r['step'],r['eval_loss']) for r in x['candidates']])
for name in ('qwen_vllm_comparison','mist_vllm_comparison','qwen_mist_vllm_comparison'):
 print(name+'_report_exists',(w/'reports'/f'{name}.json').is_file())
PY
printf 'gpu_used_total_util='; nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu --format=csv,noheader,nounits
printf 'gpu_processes='; nvidia-smi --query-compute-apps=pid,used_memory --format=csv,noheader,nounits
df -h / /root/sj-tmp | tail -2
