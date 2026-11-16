#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'time_utc='; date -u '+%F %T'
for file in "$work/qwen_round1_now.pid" "$work/vllm_install.pid"; do
 if [ -f "$file" ]; then pid=$(cat "$file"); printf '%s ' "${file##*/}"; ps -p "$pid" -o pid=,stat=,args= || true; fi
done
printf 'training_state='; cat "$work/reports/qwen_round1_now_state.txt" 2>/dev/null || true
printf '%s\n' '--- training supervisor ---'
tail -n 8 "$work/logs/qwen_round1_now.log" 2>/dev/null || true
printf '%s\n' '--- training log ---'
tail -n 10 "$work/logs/qwen3_round1.log" 2>/dev/null || true
printf '%s\n' '--- vLLM install log ---'
tail -n 5 "$work/logs/vllm_install.log" 2>/dev/null || true
printf '%s\n' '--- GPU ---'
nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu --format=csv,noheader
nvidia-smi --query-compute-apps=pid,process_name,used_gpu_memory --format=csv,noheader,nounits
df -h / /root/sj-tmp
