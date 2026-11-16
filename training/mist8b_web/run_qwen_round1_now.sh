#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
exec 9>"$work/qwen_stage1.lock"
flock -n 9 || { echo 'another Qwen training job holds the lock'; exit 1; }
state="$work/reports/qwen_round1_now_state.txt"
trap 'code=$?; printf "failed exit=%s line=%s\n" "$code" "$LINENO" > "$state"; exit "$code"' ERR
test -f "$work/reports/qwen3_download.json"
test -f "$work/reports/qwen_token_audit.json"
test -f "$work/runs/qwen3_smoke/adapter_config.json"
test -f "$work/runs/qwen3_smoke/adapter_model.safetensors"
test -f "$work/configs/qwen3_round1.yaml"
test ! -e "$work/runs/qwen3_round1"
"$work/env312/bin/python" - "$work" <<'PY'
import json,sys
from pathlib import Path
w=Path(sys.argv[1]); report=json.loads((w/'reports/qwen3_download.json').read_text())
smoke=json.loads((w/'runs/qwen3_smoke/trainer_state.json').read_text())
audit=json.loads((w/'reports/qwen_token_audit.json').read_text())
assert report['all_files_sha256_verified'] is True
assert smoke['global_step']>=10
assert audit['train']['over_cutoff']==0
print('verified Qwen base, real-model smoke, and training token audit')
PY
if [ -n "$(nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits)" ]; then
  printf 'gpu_busy\n' > "$state"
  echo 'GPU already in use; training not started' >&2
  exit 1
fi
export TOKENIZERS_PARALLELISM=false WANDB_DISABLED=true HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 CUDA_VISIBLE_DEVICES=0 PYTHONUNBUFFERED=1
printf 'training\n' > "$state"
"$work/env312/bin/llamafactory-cli" train "$work/configs/qwen3_round1.yaml" > "$work/logs/qwen3_round1.log" 2>&1
test -f "$work/runs/qwen3_round1/adapter_config.json"
test -f "$work/runs/qwen3_round1/adapter_model.safetensors"
printf 'training_complete_waiting_for_vllm_evaluation\n' > "$state"
printf 'QWEN_ROUND1_TRAINING_COMPLETE\n'
