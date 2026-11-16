#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
date -u '+%F %T UTC'
printf '%s\n' '--- Qwen task files ---'
find "$work" -maxdepth 2 -iname '*qwen*' -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort
printf '%s\n' '--- Qwen smoke artifacts ---'
find "$work/runs/qwen3_smoke" -maxdepth 2 -type f -printf '%s %p\n' 2>/dev/null | sort -n | tail -n 25
printf '%s\n' '--- Qwen log tails ---'
for f in "$work/logs"/*qwen*; do
  if [ -f "$f" ]; then printf '%s\n' "$f"; tail -n 20 "$f"; fi
done
printf '%s\n' '--- GPU and jobs ---'
nvidia-smi --query-compute-apps=pid,process_name,used_gpu_memory --format=csv,noheader,nounits
ps -eo pid,ppid,stat,args | awk '/qwen3|vllm|llamafactory/ && !/awk/ {print}'
