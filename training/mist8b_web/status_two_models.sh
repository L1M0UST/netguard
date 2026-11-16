#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'time_utc='; date -u '+%F %T'
for name in download pipeline qwen_download; do
  file="$work/$name.pid"
  if [ -f "$file" ]; then
    pid=$(cat "$file")
    printf '%s ' "$name"
    ps -p "$pid" -o pid=,stat=,args= || true
  fi
done
printf 'mist_pipeline='; cat "$work/reports/pipeline-state.txt" 2>/dev/null || true
python - "$work" <<'PY'
from pathlib import Path
import sys
w=Path(sys.argv[1]); p=w/'models/MiST-8B/model.safetensors.partial'; f=w/'models/MiST-8B/model.safetensors'
print('mist_bytes',f.stat().st_size if f.exists() else p.stat().st_size if p.exists() else 0,'of',16381517208)
q=w/'models/Qwen3-8B-ModelScope'
files=list(q.glob('*')) if q.exists() else []
print('qwen_bytes',sum(x.stat().st_size for x in files if x.is_file()),'of',16397461896)
print('qwen_verified_files',sum(x.is_file() and not x.name.endswith('.partial') for x in files))
PY
tail -n 7 "$work/logs/qwen_download.log" 2>/dev/null || true
test ! -f "$work/reports/qwen3_download.json" || cat "$work/reports/qwen3_download.json"
df -h /root/sj-tmp
