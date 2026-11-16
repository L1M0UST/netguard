#!/usr/bin/env bash
set -euo pipefail
url='https://hf-mirror.com/dreamgroup/MiST-8B/resolve/9ba377df00b9e830849fce8ebbe568a9a84774f2/model.safetensors'
start=$(date +%s)
pids=()
for n in 1 2 3 4; do
  begin=$((n*67108864))
  end=$((begin+4194303))
  curl -fsSL --connect-timeout 15 --max-time 90 -r "$begin-$end" -o /dev/null "$url" &
  pids+=("$!")
done
fail=0
for pid in "${pids[@]}"; do
  wait "$pid" || fail=$((fail+1))
done
elapsed=$(($(date +%s)-start))
printf '4 parallel downloads of 4 MiB: elapsed=%ss failures=%s\n' "$elapsed" "$fail"
ps -eo pid,ppid,args | awk '$1==401 || $1==624 || $2==401 || $2==624 {print}'
exit "$fail"
