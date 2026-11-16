set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
for name in setup download; do
  if [ -f "$work/$name.pid" ]; then
    pid=$(cat "$work/$name.pid")
    if kill -0 "$pid" 2>/dev/null; then state=running; else state=stopped; fi
    printf '%s pid=%s state=%s\n' "$name" "$pid" "$state"
  fi
done
printf '%s\n' '=== environment log ==='
tail -n 12 "$work/logs/setup_env.log" 2>/dev/null || true
printf '%s\n' '=== model download log ==='
tail -n 8 "$work/logs/download_model.log" 2>/dev/null || true
printf '%s\n' '=== model bytes ==='
find "$work/models/MiST-8B" -maxdepth 1 -type f -printf '%f %s bytes\n' 2>/dev/null || true
printf '%s\n' '=== data disk ==='
df -h "$work"
