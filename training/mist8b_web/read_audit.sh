#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
python - "$work/reports/token_audit_v2.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
for key in ['source_train','kept_train','excluded_long_train','max_tokens_before_filter','mean_tokens_before_filter','train_sha256']:
 print(key,r[key])
PY
