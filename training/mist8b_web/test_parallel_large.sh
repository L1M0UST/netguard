#!/usr/bin/env bash
set -euo pipefail
url='https://hf-mirror.com/dreamgroup/MiST-8B/resolve/9ba377df00b9e830849fce8ebbe568a9a84774f2/model.safetensors'
start=$(date +%s)
pids=()
for n in 5 6 7 8; do
  begin=$((n*268435456))
  end=$((begin+16777215))
  curl -fsSL --connect-timeout 15 --max-time 110 -r "$begin-$end" -o /dev/null "$url" &
  pids+=("$!")
done
fail=0
for pid in "${pids[@]}"; do wait "$pid" || fail=$((fail+1)); done
elapsed=$(($(date +%s)-start))
printf '4 parallel downloads of 16 MiB: elapsed=%ss failures=%s\n' "$elapsed" "$fail"
exit "$fail"
