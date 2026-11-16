#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test ! -e "$work/mist_after_qwen.pid"
nohup bash "$work/wait_mist_after_qwen.sh" > "$work/logs/mist_after_qwen.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/mist_after_qwen.pid"
printf 'MiST sequential supervisor started pid=%s\n' "$!"
