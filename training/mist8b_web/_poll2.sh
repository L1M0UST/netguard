#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'state='; cat "$work/reports/qwen_stage1_state.txt"
echo "== BASELINE =="
wc -l "$work/reports/qwen_baseline/predictions.jsonl" 2>/dev/null
if [ -f "$work/reports/qwen_baseline/summary.json" ]; then
"$work/env312/bin/python" -c "
import json;r=json.load(open('$work/reports/qwen_baseline/summary.json'));
print({k:r[k] for k in ('samples','accuracy_all_samples','macro_f1_present_classes','four_sections_rate','status_counts')})"
fi
echo "== ROUND1 TRAIN =="
grep -E "'loss'|eval_loss" "$work/logs/qwen3_round1.log" 2>/dev/null | tail -4
nvidia-smi --query-gpu=memory.used,utilization.gpu --format=csv,noheader
df -h /root/sj-tmp | tail -1
