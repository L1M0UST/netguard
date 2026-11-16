#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
hostname
for name in download token_audit; do
  if [ "$name" = download ]; then file="$work/download.pid"; else file="$work/logs/$name.pid"; fi
  if [ -f "$file" ]; then
    pid=$(cat "$file")
    if kill -0 "$pid" 2>/dev/null; then state=running; else state=stopped; fi
    printf '%s pid=%s %s\n' "$name" "$pid" "$state"
  fi
done
tail -n 4 "$work/logs/download_model.log" 2>/dev/null || true
tail -n 4 "$work/logs/token_audit.log" 2>/dev/null || true
stat -c 'model partial %s bytes' "$work/models/MiST-8B/model.safetensors.partial" 2>/dev/null || true
