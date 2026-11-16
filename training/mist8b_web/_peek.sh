#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'state='; cat "$work/reports/qwen_stage1_state.txt"
echo "== AUDIT STATS =="
"$work/env312/bin/python" - <<'PY'
import json
r=json.load(open('/root/sj-tmp/cqsec_mist8b_web_20261115/reports/qwen_token_audit.json'))
print('train', r['train']); print('dev_prompt', r['dev_prompt'])
PY
echo "== BASELINE PROGRESS =="
wc -l "$work/reports/qwen_baseline/predictions.jsonl" 2>/dev/null
grep -o "evaluated [0-9]*/[0-9]*" "$work/logs/qwen_baseline_eval.log" 2>/dev/null | tail -2
echo "== BASELINE SAMPLES =="
head -c 900 "$work/reports/qwen_baseline/predictions.jsonl" 2>/dev/null
echo
echo "== SMOKE LOSS =="
grep -E "'loss'" "$work/logs/qwen3_smoke.log" | tail -3
echo "== GPU =="
nvidia-smi --query-gpu=memory.used,utilization.gpu --format=csv,noheader
