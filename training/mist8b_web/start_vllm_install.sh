#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test ! -e "$work/vllm_install.pid"
test -f "$work/setup_vllm_qwen.sh"
nohup bash "$work/setup_vllm_qwen.sh" > "$work/logs/vllm_install.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/vllm_install.pid"
printf 'isolated vLLM install started pid=%s\n' "$!"
