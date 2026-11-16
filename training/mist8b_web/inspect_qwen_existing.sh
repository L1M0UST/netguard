#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf '%s\n' '--- Qwen configs ---'
find "$work/configs" -maxdepth 1 -iname '*qwen*' -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' | sort
for f in "$work/configs"/qwen*.yaml; do
  if [ -f "$f" ]; then printf '%s\n' "$f"; cat "$f"; fi
done
printf '%s\n' '--- Qwen run directories ---'
find "$work/runs" -maxdepth 1 -iname '*qwen*' -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort
printf '%s\n' '--- Qwen pipeline processes ---'
ps -eo pid,ppid,stat,args | awk '/qwen3_(smoke|profile|round1)|llamafactory-cli/ && !/awk/ {print}'
