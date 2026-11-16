#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf '%s\n' '--- GPU ---'
nvidia-smi --query-gpu=name,memory.total,memory.free,utilization.gpu,driver_version --format=csv,noheader
printf '%s\n' '--- GPU compute processes ---'
nvidia-smi --query-compute-apps=pid,process_name,used_gpu_memory --format=csv,noheader,nounits
printf '%s\n' '--- Disk ---'
df -h / /root/sj-tmp /root/sj-fs
printf '%s\n' '--- Tools ---'
for cmd in vllm llama-cli llama-server docker git cmake nvcc; do
  if command -v "$cmd" >/dev/null 2>&1; then command -v "$cmd"; fi
done
printf '%s\n' '--- Qwen and MiST verified metadata ---'
cat "$work/reports/qwen3_download.json" 2>/dev/null || true
cat "$work/reports/model-verified.txt" 2>/dev/null || true
printf '%s\n' '--- Earlier pipeline ---'
cat "$work/reports/pipeline-state.txt" 2>/dev/null || true
printf '%s\n' '--- Active task-owned processes ---'
ps -eo pid,ppid,stat,args | awk -v w="$work" 'index($0,w) && /run_pipeline|llamafactory|evaluate_web|vllm/ && !/awk/ {print}'
