#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test "$(cat "$work/reports/pipeline-state.txt")" = waiting_for_verified_model
test ! -e "$work/reports/baseline"
test ! -e "$work/evaluate_web_v1.backup.py"
printf '%s  %s\n' '3756bad5976d18d53fce0a6548fc4795515597d716d2ac7d83d7579748f9a171' "$work/evaluate_web_v2.py" | sha256sum -c -
cp -p "$work/evaluate_web.py" "$work/evaluate_web_v1.backup.py"
mv "$work/evaluate_web_v2.py" "$work/evaluate_web.py"
test ! -e "$work/report_monitor.pid"
nohup bash "$work/report_monitor.sh" > "$work/logs/report_monitor.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/report_monitor.pid"
printf 'evaluation v2 activated; report monitor pid=%s\n' "$!"
