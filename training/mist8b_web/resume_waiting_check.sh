set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test "$(cat "$work/reports/pipeline-state.txt")" = waiting_for_verified_model
for entry in 'pipeline:run_pipeline_v2.sh' 'report_monitor:report_monitor.sh' 'export_monitor:export_monitor.sh'; do
  name=${entry%%:*}
  script=${entry#*:}
  file="$work/$name.pid"
  pid=$(cat "$file" 2>/dev/null || true)
  if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$work/$script"; then continue; fi
  nohup bash "$work/$script" >> "$work/logs/$name.log" 2>&1 < /dev/null &
  printf '%s\n' "$!" > "$file"
  printf 'resumed %s pid=%s\n' "$name" "$!"
done
