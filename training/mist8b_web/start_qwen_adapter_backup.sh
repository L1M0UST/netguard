#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test ! -e "$work/qwen_adapter_backup.pid"
nohup bash "$work/wait_qwen_adapter_backup.sh" > "$work/logs/qwen_adapter_backup.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/qwen_adapter_backup.pid"
printf 'adapter backup supervisor started pid=%s\n' "$!"
