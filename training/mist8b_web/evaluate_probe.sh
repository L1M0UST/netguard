#!/usr/bin/env bash
set -euo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
export TOKENIZERS_PARALLELISM=false HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 CUDA_VISIBLE_DEVICES=0
test ! -e "$work/data/probe_dev.jsonl"
test ! -e "$work/reports/probe_baseline"
test ! -e "$work/reports/probe_adapter"
head -n 2 "$work/data/web_fit_v2/dev.jsonl" > "$work/data/probe_dev.jsonl"
py="$work/env312/bin/python"
"$py" "$work/evaluate_web.py" --model "$work/models/probe-random-qwen3-v2" --data "$work/data/probe_dev.jsonl" \
  --output "$work/reports/probe_baseline" --max-new-tokens 16 > "$work/logs/probe_baseline.log" 2>&1
"$py" "$work/evaluate_web.py" --model "$work/models/probe-random-qwen3-v2" --adapter "$work/runs/infra_probe_v2" \
  --data "$work/data/probe_dev.jsonl" --output "$work/reports/probe_adapter" --max-new-tokens 16 > "$work/logs/probe_adapter.log" 2>&1
"$py" - "$work" <<'PY'
from pathlib import Path
import json,sys
w=Path(sys.argv[1]); a=json.loads((w/'reports/probe_baseline/summary.json').read_text()); b=json.loads((w/'reports/probe_adapter/summary.json').read_text())
assert a['samples']==b['samples']==2 and a['data_sha256']==b['data_sha256']
assert all(not k.startswith('inference_error:') for k in a['status_counts']|b['status_counts'])
assert 'four_sections_rate' in a and 'four_sections_rate' in b
print('random-model baseline and adapter evaluation verified on two records')
PY
