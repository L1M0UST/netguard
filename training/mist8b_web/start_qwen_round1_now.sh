#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test ! -e "$work/qwen_round1_now.pid"
test -f "$work/run_qwen_round1_now.sh"
nohup bash "$work/run_qwen_round1_now.sh" > "$work/logs/qwen_round1_now.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/qwen_round1_now.pid"
printf 'Qwen3 round1 supervisor started pid=%s\n' "$!"
