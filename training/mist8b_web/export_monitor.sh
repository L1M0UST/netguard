#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
while true; do
  state=$(cat "$work/reports/pipeline-state.txt" 2>/dev/null || true)
  if [ "$state" = complete ] && [ -f "$work/reports/comparison.json" ]; then
    "$work/env312/bin/python" "$work/export_artifact.py" > "$work/logs/export.log" 2>&1
    exit 0
  fi
  case "$state" in pipeline_failed*|download_failed*|gpu_already_in_use) exit 1 ;; esac
  if [ "$state" = complete ]; then
    pid=$(cat "$work/report_monitor.pid" 2>/dev/null || true)
  else
    pid=$(cat "$work/pipeline.pid" 2>/dev/null || true)
  fi
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || [ "$(ps -o stat= -p "$pid" | cut -c1)" = Z ]; then exit 1; fi
  sleep 20
done
