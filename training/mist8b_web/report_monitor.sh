#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
while true; do
  state=$(cat "$work/reports/pipeline-state.txt" 2>/dev/null || true)
  if [ "$state" = complete ]; then
    "$work/env312/bin/python" "$work/compare_web.py" > "$work/logs/comparison.log" 2>&1
    exit 0
  fi
  case "$state" in pipeline_failed*|download_failed*|gpu_already_in_use) exit 1 ;; esac
  pid=$(cat "$work/pipeline.pid" 2>/dev/null || true)
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || [ "$(ps -o stat= -p "$pid" | cut -c1)" = Z ]; then
    exit 1
  fi
  sleep 20
done
