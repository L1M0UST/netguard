#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test ! -e "$work/export_monitor.pid"
test -f "$work/export_artifact.py"
test -f "$work/export_monitor.sh"
nohup bash "$work/export_monitor.sh" > "$work/logs/export_monitor.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/export_monitor.pid"
printf 'export monitor started pid=%s\n' "$!"
