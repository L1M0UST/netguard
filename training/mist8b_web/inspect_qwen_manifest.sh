#!/usr/bin/env bash
set -euo pipefail
python - <<'PY'
import json,urllib.request
url='https://www.modelscope.cn/api/v1/models/Qwen/Qwen3-8B/repo/files?Revision=master&Recursive=true'
with urllib.request.urlopen(url,timeout=20) as r:
 obj=json.load(r)
print('root keys',list(obj))
data=obj.get('Data') or {}
print('data keys',list(data))
files=data.get('Files') or []
for x in files:
 print(json.dumps({k:x.get(k) for k in ('Name','Path','Type','Size','Sha256','Revision')},ensure_ascii=False))
PY
