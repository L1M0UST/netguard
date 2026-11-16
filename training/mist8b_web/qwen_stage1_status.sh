#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'time_utc='; date -u '+%F %T'
printf 'state='; cat "$work/reports/qwen_stage1_state.txt" 2>/dev/null || echo missing
printf 'pid='; cat "$work/qwen_stage1.pid" 2>/dev/null || echo none
pid=$(cat "$work/qwen_stage1.pid" 2>/dev/null || true)
if [ -n "$pid" ]; then ps -p "$pid" -o pid=,stat=,etime=,args= 2>/dev/null || echo "process not running"; fi
echo "== GPU =="
nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu,temperature.gpu,power.draw --format=csv,noheader
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader
echo "== DISK =="
df -h /root/sj-tmp / | tail -2
echo "== RUNS =="
du -sh "$work"/runs/qwen3_* 2>/dev/null
ls -lh "$work"/runs/qwen3_round1/checkpoint-* 2>/dev/null | tail -5
echo "== LOG TAILS =="
for f in qwen_token_audit qwen3_smoke qwen_baseline_eval qwen3_round1 qwen_adapter_eval; do
  echo "--- $f"
  tail -n 4 "$work/logs/$f.log" 2>/dev/null || echo "(no log)"
done
echo "== TRAIN METRICS =="
grep -E "'loss'|eval_loss" "$work/logs/qwen3_round1.log" 2>/dev/null | tail -5
echo "== REPORTS =="
ls -la "$work/reports/qwen_baseline" "$work/reports/qwen_adapter" 2>/dev/null
