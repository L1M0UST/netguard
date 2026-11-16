#!/usr/bin/env bash
cd "$(dirname "$0")"
log=poll_qwen_stage1.log
: > "$log"
for i in $(seq 1 72); do
  ts=$(date '+%F %T')
  out=$(python remote_client.py run _poll_compact.sh --timeout 90 2>&1)
  key=$(printf '%s' "$out" | grep -E "^state=|baseline_count=|adapter_count=|train_progress=|'loss'|'eval_loss'|COMPARISON|accuracy|macro_f1|paired" | tr '\n' '; ')
  echo "$ts $key" >> "$log"
  case "$out" in
    *state=complete*) echo "COMPLETE $ts" >> "$log"; exit 0;;
    *state=failed*) echo "FAILED $ts" >> "$log"; exit 2;;
  esac
  sleep 300
done
echo "TIMEOUT $(date '+%F %T')" >> "$log"
exit 3
