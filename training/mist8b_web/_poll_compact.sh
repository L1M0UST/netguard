#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
py="$work/env312/bin/python"
printf 'state='; cat "$work/reports/qwen_stage1_state.txt" 2>/dev/null || echo missing
printf 'baseline_count='; wc -l < "$work/reports/qwen_baseline/predictions.jsonl" 2>/dev/null || echo 0
printf 'adapter_count='; wc -l < "$work/reports/qwen_adapter/predictions.jsonl" 2>/dev/null || echo 0
printf 'train_progress='; grep -oE "[0-9]+/1839 \[[0-9:<,]+" "$work/logs/qwen3_round1.log" 2>/dev/null | tail -1 || echo none
grep -E "'loss'|'eval_loss'" "$work/logs/qwen3_round1.log" 2>/dev/null | tail -2
printf 'gpu='; nvidia-smi --query-gpu=memory.used,utilization.gpu --format=csv,noheader
printf 'disk='; df -h /root/sj-tmp | awk 'NR==2{print $4" free"}'
if [ -f "$work/reports/qwen_comparison.json" ]; then
  echo "== COMPARISON HEAD =="
  "$py" -c "
import json;r=json.load(open('$work/reports/qwen_comparison.json'))
print('paired',r['paired']); 
for k in ('accuracy_all_samples','macro_f1_present_classes','four_sections_rate'):
  print(k, round((r['before'][k] or 0)*100,2),'->',round((r['after'][k] or 0)*100,2))"
fi
