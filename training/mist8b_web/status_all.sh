#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
for name in setup_env setup_env312 download_model; do
  pidfile="$work/logs/$name.pid"
  if [ -e "$pidfile" ]; then
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then state=running; else state=stopped; fi
    printf '%s pid=%s state=%s\n' "$name" "$pid" "$state"
  fi
  if [ -e "$work/logs/$name.log" ]; then tail -n 6 "$work/logs/$name.log"; fi
done
stat -c 'model partial %s bytes, mtime %y' "$work/models/MiST-8B/model.safetensors.partial" 2>/dev/null || true
df -h /root/sj-tmp
ls -lah /root/sj-fs | head -20
