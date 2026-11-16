#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
for name in qwen_round1_now qwen_vllm_pipeline qwen_adapter_backup qwen_checkpoint_monitor; do
  printf '%s: ' "$name"
  cat "$work/reports/${name}_state.txt" 2>/dev/null || echo missing
  pid=$(cat "$work/${name}.pid")
  ps -o pid=,stat=,args= -p "$pid" | cut -c1-140
done
printf 'vllm_install: '; cat "$work/reports/vllm_install_state.txt"
printf 'checkpoint_candidates: '
"$work/env312/bin/python" - "$work/reports/qwen_preserved_checkpoints.json" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); print(len(json.loads(p.read_text())['candidates']) if p.exists() else 'not yet')
PY
