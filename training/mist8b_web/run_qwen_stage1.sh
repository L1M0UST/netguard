#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
mkdir -p logs reports runs exports
exec 9>"$work/qwen_stage1.lock"
flock -n 9 || { echo 'another qwen stage1 run is active'; exit 1; }

export TOKENIZERS_PARALLELISM=false
export WANDB_DISABLED=true
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export PYTHONUNBUFFERED=1
export CUDA_VISIBLE_DEVICES=0

py="$work/env312/bin/python"
cli="$work/env312/bin/llamafactory-cli"
state="$work/reports/qwen_stage1_state.txt"
model="$work/models/Qwen3-8B-ModelScope"
data="$work/data/web_fit_v2"
trap 'code=$?; printf "failed exit=%s line=%s\n" "$code" "$LINENO" > "$state"; exit "$code"' ERR

test -x "$py"
test -x "$cli"
test -f "$model/config.json"
test -f "$model/model.safetensors.index.json"
test -f "$data/train.jsonl"
test -f "$data/dev.jsonl"
test -f "$work/reports/qwen3_download.json"
"$py" - "$work/reports/qwen3_download.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r.get('all_files_sha256_verified') is True, r
print('model download verified:',r['model_dir'])
PY
avail_kb=$(df -Pk "$work" | awk 'NR==2{print $4}')
if [ "$avail_kb" -lt 6291456 ]; then echo "insufficient disk: ${avail_kb}KB" >&2; exit 1; fi
if [ -n "$(nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits)" ]; then
  echo 'GPU already in use' >&2; nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader; exit 1
fi

printf 'token_audit\n' > "$state"
"$py" "$work/audit_qwen_tokens.py" > "$work/logs/qwen_token_audit.log" 2>&1
"$py" - "$work/reports/qwen_token_audit.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
print('train max tokens',r['train']['max'],'over cutoff',r['train']['over_cutoff'],'of',r['train']['count'])
PY

printf 'smoke_train\n' > "$state"
test ! -e "$work/runs/qwen3_smoke"
"$cli" train "$work/configs/qwen3_smoke.yaml" > "$work/logs/qwen3_smoke.log" 2>&1
test -f "$work/runs/qwen3_smoke/adapter_config.json"

printf 'baseline_eval\n' > "$state"
test ! -e "$work/reports/qwen_baseline"
"$py" "$work/evaluate_web.py" --model "$model" \
  --data "$data/dev.jsonl" --output "$work/reports/qwen_baseline" \
  > "$work/logs/qwen_baseline_eval.log" 2>&1
"$py" - "$work/reports/qwen_baseline/summary.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1])); bad=sum(v for k,v in r['status_counts'].items() if k.startswith('inference_error:'))
if bad>max(2,r['samples']*0.01): raise SystemExit('baseline inference errors exceed threshold')
print('baseline ok:',r['samples'],'samples;',bad,'inference errors')
PY

printf 'train_round1\n' > "$state"
test ! -e "$work/runs/qwen3_round1"
"$cli" train "$work/configs/qwen3_round1.yaml" > "$work/logs/qwen3_round1.log" 2>&1
test -f "$work/runs/qwen3_round1/adapter_config.json"

printf 'adapter_eval\n' > "$state"
test ! -e "$work/reports/qwen_adapter"
"$py" "$work/evaluate_web.py" --model "$model" --adapter "$work/runs/qwen3_round1" \
  --data "$data/dev.jsonl" --output "$work/reports/qwen_adapter" \
  > "$work/logs/qwen_adapter_eval.log" 2>&1

printf 'compare\n' > "$state"
"$py" "$work/compare_qwen_web.py" > "$work/logs/qwen_compare.log" 2>&1

printf 'export\n' > "$state"
"$py" "$work/export_qwen_artifact.py" > "$work/logs/qwen_export.log" 2>&1

printf 'complete\n' > "$state"
printf 'QWEN_STAGE1_COMPLETE\n'
