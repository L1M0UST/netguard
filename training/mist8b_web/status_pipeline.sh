#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'host='
hostname
for file in "$work/download.pid" "$work/pipeline.pid"; do
  if [ -f "$file" ]; then
    pid=$(cat "$file")
    printf '%s ' "${file##*/}"
    ps -p "$pid" -o pid=,stat=,args= || true
  fi
done
printf 'pipeline_state='
cat "$work/reports/pipeline-state.txt" 2>/dev/null || true
tail -n 6 "$work/logs/pipeline.log" 2>/dev/null || true
for name in smoke baseline_eval profile round1 adapter_eval; do
  if [ -f "$work/logs/$name.log" ]; then
    printf '%s log tail:\n' "$name"
    tail -n 3 "$work/logs/$name.log"
  fi
done
if [ -f "$work/models/MiST-8B/model.safetensors.partial" ]; then
  stat -c 'partial_bytes=%s mtime=%y' "$work/models/MiST-8B/model.safetensors.partial"
fi
if [ -f "$work/reports/model-verified.txt" ]; then cat "$work/reports/model-verified.txt"; fi
nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu --format=csv,noheader
