#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test ! -e "$work/qwen_checkpoint_monitor.pid"
nohup "$work/env312/bin/python" "$work/preserve_qwen_checkpoints.py" > "$work/logs/qwen_checkpoint_monitor.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/qwen_checkpoint_monitor.pid"
printf 'checkpoint monitor started pid=%s\n' "$!"
