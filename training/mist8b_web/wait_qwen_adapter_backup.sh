#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
state="$work/reports/qwen_adapter_backup_state.txt"
exec 8>"$work/qwen_adapter_backup.lock"
flock -n 8 || exit 1
trap 'code=$?; printf "failed exit=%s line=%s\n" "$code" "$LINENO" > "$state"; exit "$code"' ERR
printf 'waiting_for_training\n' > "$state"
while :; do
  train=$(cat "$work/reports/qwen_round1_now_state.txt" 2>/dev/null || true)
  case "$train" in
    training_complete_waiting_for_vllm_evaluation) break;;
    failed*|gpu_busy) printf 'training_failed_or_blocked: %s\n' "$train" > "$state"; exit 1;;
  esac
  pid=$(cat "$work/qwen_round1_now.pid" 2>/dev/null || true)
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || [ "$(ps -o stat= -p "$pid" | cut -c1)" = Z ]; then
    printf 'training_supervisor_stopped_unexpectedly\n' > "$state"; exit 1
  fi
  sleep 20
done
printf 'exporting_adapter\n' > "$state"
"$work/env312/bin/python" "$work/export_qwen_adapter.py"
printf 'complete\n' > "$state"
