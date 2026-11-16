#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'time_utc='; date -u +%FT%TZ
for key in qwen_round1_now vllm_install qwen_vllm_pipeline; do
  printf '%s_state=' "$key"
  cat "$work/reports/${key}_state.txt" 2>/dev/null || echo missing
  pid=$(cat "$work/${key}.pid" 2>/dev/null || true)
  if [ -n "$pid" ]; then ps -p "$pid" -o pid=,stat=,args= | cut -c1-120 || true; fi
done
printf '%s\n' 'LATEST_TRAIN_PROGRESS'
tr '\r' '\n' < "$work/logs/qwen3_round1.log" | tail -8
printf '%s\n' 'VLLM_INSTALL_TAIL'
tail -6 "$work/logs/vllm_install.log" 2>/dev/null || true
printf '%s\n' 'EVALUATION_PIPELINE_TAIL'
tail -6 "$work/logs/qwen_vllm_pipeline.log" 2>/dev/null || true
nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu --format=csv,noheader,nounits
df -h / /root/sj-tmp | tail -2
