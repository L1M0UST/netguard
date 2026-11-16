#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
mkdir -p "$work/logs"
if [ -e "$work/reports/model-verified.txt" ]; then
  printf 'model already verified\n'
  exit 0
fi
if [ -e "$work/download.pid" ]; then
  old=$(cat "$work/download.pid")
  if [ -r "/proc/$old/cmdline" ] && tr '\0' ' ' < "/proc/$old/cmdline" | grep -Fq "$work/download_model.sh"; then
    printf 'existing download is active pid=%s\n' "$old"
    exit 0
  fi
fi
nohup bash "$work/download_model.sh" >> "$work/logs/download_model.log" 2>&1 < /dev/null &
pid=$!
printf '%s\n' "$pid" > "$work/download.pid"
printf 'download resumed pid=%s\n' "$pid"
