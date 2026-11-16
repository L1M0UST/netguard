#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test ! -e "$work/env312"
nohup bash "$work/setup_env_fast.sh" > "$work/logs/setup_env312.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/logs/setup_env312.pid"
printf 'started alternate setup pid=%s\n' "$!"
