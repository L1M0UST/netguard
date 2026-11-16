#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
hostname
for item in "$work/download.pid" "$work/logs/token_audit_v2.pid"; do
  if [ -f "$item" ]; then
    pid=$(cat "$item")
    if kill -0 "$pid" 2>/dev/null; then state=running; else state=stopped; fi
    printf '%s pid=%s %s\n' "${item##*/}" "$pid" "$state"
  fi
done
tail -n 6 "$work/logs/token_audit_v2.log" 2>/dev/null || true
tail -n 3 "$work/logs/download_model.log" 2>/dev/null || true
stat -c 'model partial %s bytes' "$work/models/MiST-8B/model.safetensors.partial" 2>/dev/null || true
test ! -e "$work/reports/model-verified.txt" || cat "$work/reports/model-verified.txt"
