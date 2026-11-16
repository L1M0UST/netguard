#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
file="$work/models/MiST-8B/model.safetensors.partial"
stat --printf='file logical_bytes=%s allocated_blocks=%b block_bytes=%B allocated_bytes=%b*%B\n' "$file"
ls -lahs "$file"
if command -v filefrag >/dev/null 2>&1; then
  filefrag -v "$file" | tail -n 18
fi
if command -v lsof >/dev/null 2>&1; then
  lsof -n -- "$file" | head -n 10
fi
printf '%s\n' '--- Relevant training configurations ---'
for p in "$work/configs/smoke.yaml" "$work/configs/profile.yaml" "$work/configs/round1.yaml"; do
  printf '%s\n' "$p"
  awk '/output_dir:|lora_rank:|lora_target:|save_steps:|save_total_limit:|gradient_accumulation_steps:|max_steps:|num_train_epochs:/' "$p"
done
