#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test ! -e "$work/pipeline.pid"
test -f "$work/run_pipeline.sh"
nohup bash "$work/run_pipeline.sh" > "$work/logs/pipeline.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/pipeline.pid"
printf 'pipeline started pid=%s\n' "$!"
