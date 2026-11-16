#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
python - "$work/logs/infra_probe_v2.log" "$work/reports/probe_baseline/summary.json" "$work/reports/probe_adapter/summary.json" <<'PY'
import json,re,sys
text=open(sys.argv[1],encoding='utf-8').read()
for pattern in ('4-bit','trainable params','train_runtime'):
 found=[line.strip() for line in text.splitlines() if pattern.lower() in line.lower()]
 print(pattern,found[-1] if found else 'not found')
for p in sys.argv[2:]:
 x=json.load(open(p,encoding='utf-8'))
 print(p.split('/')[-2],x['samples'],x['status_counts'],'four_sections_rate',x['four_sections_rate'])
PY
