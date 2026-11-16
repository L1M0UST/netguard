#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test ! -e "$work/qwen_download.pid"
test -f "$work/download_qwen_modelscope.py"
nohup python -u "$work/download_qwen_modelscope.py" > "$work/logs/qwen_download.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/qwen_download.pid"
printf 'Qwen3-8B ModelScope download pid=%s\n' "$!"
