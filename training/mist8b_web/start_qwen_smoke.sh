#!/usr/bin/env bash
set -euo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
test ! -e "$work/qwen_smoke.pid"
test ! -e "$work/runs/qwen3_smoke"
test -f "$work/configs/qwen3_smoke.yaml"
if [ -n "$(nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits)" ]; then
  echo 'GPU has active compute; smoke not started' >&2
  exit 1
fi
export TOKENIZERS_PARALLELISM=false WANDB_DISABLED=true HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 CUDA_VISIBLE_DEVICES=0
nohup "$work/env312/bin/llamafactory-cli" train "$work/configs/qwen3_smoke.yaml" > "$work/logs/qwen3_smoke.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/qwen_smoke.pid"
printf 'Qwen3 real 8B QLoRA 5-step smoke started pid=%s\n' "$!"
