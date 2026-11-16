#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test ! -e "$work/qwen_vllm_pipeline.pid"
nohup bash "$work/wait_qwen_vllm.sh" > "$work/logs/qwen_vllm_pipeline.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/qwen_vllm_pipeline.pid"
printf 'vLLM evaluation supervisor started pid=%s\n' "$!"
