#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
mkdir -p logs reports runs
exec 9>"$work/pipeline.lock"
flock -n 9 || { echo 'another pipeline is running'; exit 1; }
export TOKENIZERS_PARALLELISM=false
export WANDB_DISABLED=true
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export PYTHONUNBUFFERED=1
export CUDA_VISIBLE_DEVICES=0
py="$work/env312/bin/python"
cli="$work/env312/bin/llamafactory-cli"
trap 'code=$?; printf "pipeline_failed exit=%s line=%s\n" "$code" "$LINENO" > "$work/reports/pipeline-state.txt"; exit "$code"' ERR
printf 'waiting_for_verified_model\n' > "$work/reports/pipeline-state.txt"
test -x "$py"
test -x "$cli"
test -f "$work/reports/token_audit_v2.json"
test -f "$work/models/MiST-8B-transformers4/COMPATIBILITY.json"
while [ ! -e "$work/reports/model-verified.txt" ]; do
  pid=$(cat "$work/download.pid" 2>/dev/null || true)
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || [ "$(ps -o stat= -p "$pid" | cut -c1)" = Z ]; then
    if [ -f "$work/models/MiST-8B/model.safetensors" ]; then
      echo 'final model exists without verification; manual checksum investigation required' >&2
    else
      echo 'download is stopped before verification; pipeline halted' >&2
    fi
    printf 'download_failed_before_verification\n' > "$work/reports/pipeline-state.txt"
    exit 1
  fi
  sleep 20
done
if [ -n "$(nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits)" ]; then
  printf 'gpu_already_in_use\n' > "$work/reports/pipeline-state.txt"
  echo 'GPU already in use; pipeline halted' >&2
  exit 1
fi
printf 'running_smoke\n' > "$work/reports/pipeline-state.txt"
test ! -e "$work/runs/smoke"
"$cli" train "$work/configs/smoke.yaml" > "$work/logs/smoke.log" 2>&1
test -f "$work/runs/smoke/adapter_config.json"
printf 'running_baseline_eval\n' > "$work/reports/pipeline-state.txt"
"$py" "$work/evaluate_web.py" --model "$work/models/MiST-8B-transformers4" \
  --data "$work/data/web_fit_v2/dev.jsonl" --output "$work/reports/baseline" \
  > "$work/logs/baseline_eval.log" 2>&1
"$py" - "$work/reports/baseline/summary.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1])); bad=sum(v for k,v in r['status_counts'].items() if k.startswith('inference_error:'))
if bad>max(2, r['samples']*0.01): raise SystemExit('baseline inference errors exceed threshold')
print('baseline operational check passed:',r['samples'],'samples;',bad,'inference errors')
PY
printf 'running_profile\n' > "$work/reports/pipeline-state.txt"
test ! -e "$work/runs/profile"
"$cli" train "$work/configs/profile.yaml" > "$work/logs/profile.log" 2>&1
test -f "$work/runs/profile/adapter_config.json"
printf 'training_round1\n' > "$work/reports/pipeline-state.txt"
test ! -e "$work/runs/round1"
"$cli" train "$work/configs/round1.yaml" > "$work/logs/round1.log" 2>&1
test -f "$work/runs/round1/adapter_config.json"
printf 'running_adapter_eval\n' > "$work/reports/pipeline-state.txt"
"$py" "$work/evaluate_web.py" --model "$work/models/MiST-8B-transformers4" \
  --adapter "$work/runs/round1" --data "$work/data/web_fit_v2/dev.jsonl" \
  --output "$work/reports/adapter" > "$work/logs/adapter_eval.log" 2>&1
printf 'complete\n' > "$work/reports/pipeline-state.txt"
printf 'PIPELINE_COMPLETE\n'
