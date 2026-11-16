#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
state="$work/reports/qwen_vllm_pipeline_state.txt"
exec 8>"$work/qwen_vllm_pipeline.lock"
flock -n 8 || { echo 'vLLM evaluation supervisor already running'; exit 1; }
trap 'code=$?; printf "failed exit=%s line=%s\n" "$code" "$LINENO" > "$state"; exit "$code"' ERR
printf 'waiting_for_training_and_vllm\n' > "$state"
while :; do
  train=$(cat "$work/reports/qwen_round1_now_state.txt" 2>/dev/null || true)
  install=$(cat "$work/reports/vllm_install_state.txt" 2>/dev/null || true)
  case "$train" in failed*|gpu_busy) printf 'training_failed_or_blocked: %s\n' "$train" > "$state"; exit 1;; esac
  case "$install" in failed*) printf 'vllm_install_failed: %s\n' "$install" > "$state"; exit 1;; esac
  if [ "$train" = 'training_complete_waiting_for_vllm_evaluation' ] && [ "$install" = 'installed_untested' ]; then break; fi
  if [ "$train" = training ]; then
    pid=$(cat "$work/qwen_round1_now.pid" 2>/dev/null || true)
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || [ "$(ps -o stat= -p "$pid" | cut -c1)" = Z ]; then
      printf 'training_supervisor_stopped_unexpectedly\n' > "$state"; exit 1
    fi
  fi
  sleep 20
done
for attempt in $(seq 1 30); do
  if [ -z "$(nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits)" ]; then break; fi
  printf 'waiting_for_gpu_release\n' > "$state"
  sleep 10
done
if [ -n "$(nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits)" ]; then
  printf 'blocked_gpu_busy\n' > "$state"; exit 1
fi
test -f "$work/runs/qwen3_round1/adapter_model.safetensors"
test -x /root/qwen3-vllm-085/bin/python
export TOKENIZERS_PARALLELISM=false HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 CUDA_VISIBLE_DEVICES=0 PYTHONUNBUFFERED=1
printf 'running_vllm_paired_evaluation\n' > "$state"
/root/qwen3-vllm-085/bin/python "$work/evaluate_qwen_vllm.py" > "$work/logs/qwen_vllm_evaluation.log" 2>&1
printf 'vllm_evaluation_verified\n' > "$work/reports/vllm_install_state.txt"
printf 'comparing\n' > "$state"
"$work/env312/bin/python" "$work/compare_qwen_vllm.py"
printf 'exporting\n' > "$state"
"$work/env312/bin/python" "$work/export_qwen_vllm.py"
printf 'complete\n' > "$state"
printf 'QWEN_TRAIN_AND_VLLM_EVALUATION_COMPLETE\n'
