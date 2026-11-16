#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
state="$work/reports/mist_after_qwen_state.txt"
exec 8>"$work/mist_after_qwen.lock"
flock -n 8 || { echo 'MiST sequential supervisor already running'; exit 1; }
trap 'code=$?; printf "failed exit=%s line=%s\n" "$code" "$LINENO" > "$state"; exit "$code"' ERR
printf 'waiting_for_qwen_training_and_evaluation\n' > "$state"
while :; do
  qwen=$(cat "$work/reports/qwen_vllm_pipeline_state.txt" 2>/dev/null || true)
  case "$qwen" in
    complete) break;;
    failed*|training_failed*|training_supervisor_stopped*|vllm_install_failed*|blocked_gpu_busy*)
      printf 'blocked_by_qwen_evaluation: %s\n' "$qwen" > "$state"; exit 1;;
  esac
  pid=$(cat "$work/qwen_vllm_pipeline.pid" 2>/dev/null || true)
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || [ "$(ps -o stat= -p "$pid" | cut -c1)" = Z ]; then
    printf 'blocked_qwen_supervisor_stopped\n' > "$state"; exit 1
  fi
  sleep 30
done
exec 9>"$work/pipeline.lock"
flock -n 9 || { printf 'blocked_another_mist_pipeline_running\n' > "$state"; exit 1; }
for attempt in $(seq 1 30); do
  if [ -z "$(nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits)" ]; then break; fi
  printf 'waiting_for_gpu_release\n' > "$state"
  sleep 10
done
if [ -n "$(nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits)" ]; then
  printf 'blocked_gpu_busy\n' > "$state"; exit 1
fi
test -f "$work/reports/model-verified.txt"
test -f "$work/reports/token_audit_v2.json"
test -f "$work/models/MiST-8B-transformers4/COMPATIBILITY.json"
test ! -e "$work/runs/smoke"
test ! -e "$work/runs/round1"
export TOKENIZERS_PARALLELISM=false WANDB_DISABLED=true HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 CUDA_VISIBLE_DEVICES=0 PYTHONUNBUFFERED=1
printf 'mist_smoke\n' > "$state"
"$work/env312/bin/llamafactory-cli" train "$work/configs/smoke.yaml" > "$work/logs/mist_smoke_after_qwen.log" 2>&1
"$work/env312/bin/python" - "$work/runs/smoke/trainer_state.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['global_step']>=5
print('real MiST 5-step smoke passed')
PY
printf 'training_mist\n' > "$state"
nohup "$work/env312/bin/python" "$work/preserve_mist_checkpoints.py" > "$work/logs/mist_checkpoint_monitor.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/mist_checkpoint_monitor.pid"
"$work/env312/bin/llamafactory-cli" train "$work/configs/round1.yaml" > "$work/logs/mist_round1_after_qwen.log" 2>&1
test -f "$work/runs/round1/adapter_model.safetensors"
test -f "$work/runs/round1/adapter_config.json"
printf 'mist_trained_backing_up\n' > "$state"
"$work/env312/bin/python" "$work/export_mist_vllm.py"
for attempt in $(seq 1 30); do
  if [ -z "$(nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits)" ]; then break; fi
  sleep 10
done
if [ -n "$(nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits)" ]; then
  printf 'mist_trained_gpu_busy\n' > "$state"; exit 1
fi
printf 'evaluating_mist_with_vllm\n' > "$state"
/root/qwen3-vllm-085/bin/python "$work/evaluate_mist_vllm.py" > "$work/logs/mist_vllm_evaluation.log" 2>&1
printf 'comparing_models\n' > "$state"
"$work/env312/bin/python" "$work/compare_mist_vllm.py"
"$work/env312/bin/python" "$work/compare_qwen_mist_vllm.py"
printf 'exporting_mist_and_comparison\n' > "$state"
"$work/env312/bin/python" "$work/export_mist_vllm.py" --evaluated
printf 'complete\n' > "$state"
printf 'MIST_AFTER_QWEN_COMPLETE\n'
