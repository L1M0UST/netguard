#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
for f in "$work/reports/qwen_stage1_state.txt" "$work/qwen_stage1.pid" "$work/logs/qwen_stage1_runner.log"; do
 if [ -f "$f" ]; then printf '%s\n' "--- $f"; cat "$f"; fi
done
printf '%s\n' '--- Previous Qwen stage runner ---'
cat "$work/run_qwen_stage1.sh" 2>/dev/null || true
printf '%s\n' '--- Smoke train metrics ---'
tail -n 25 "$work/logs/qwen3_smoke.log" 2>/dev/null || true
printf '%s\n' '--- Qwen baseline partial output ---'
wc -l "$work/reports/qwen_baseline/predictions.jsonl" 2>/dev/null || true
test ! -e "$work/reports/qwen_baseline/summary.json" || cat "$work/reports/qwen_baseline/summary.json"
printf '%s\n' '--- Live GPU/processes ---'
nvidia-smi --query-gpu=name,memory.free,utilization.gpu --format=csv,noheader
ps -eo pid,ppid,stat,args | awk -v w="$work" 'index($0,w) && /qwen_stage1|llamafactory|evaluate_web|vllm/ && !/awk/ {print}'
