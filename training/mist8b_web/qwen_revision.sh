#!/usr/bin/env bash
set -euo pipefail
python - <<'PY'
import json,urllib.request
base='https://www.modelscope.cn/api/v1/models/Qwen/Qwen3-8B'
for suffix in ('','/repo/files?Revision=master&Recursive=true'):
 with urllib.request.urlopen(base+suffix,timeout=20) as r: obj=json.load(r)
 data=obj.get('Data') or {}
 print('MODEL_METADATA' if not suffix else 'FILES_LATEST_COMMITTER')
 if suffix:
  print(json.dumps(data.get('LatestCommitter'),ensure_ascii=False))
 else:
  for k in ('Revision','ModelRevision','DefaultRevision','LatestCommitter','Id','Name'):
   if k in data: print(k,json.dumps(data[k],ensure_ascii=False))
PY
