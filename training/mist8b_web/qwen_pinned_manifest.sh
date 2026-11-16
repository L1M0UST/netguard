#!/usr/bin/env bash
set -euo pipefail
python - <<'PY'
import json,urllib.parse,urllib.request
rev='26028140be3ee69b82b1d1450179ab71bb1121b9'
url='https://www.modelscope.cn/api/v1/models/Qwen/Qwen3-8B/repo/files?'+urllib.parse.urlencode({'Revision':rev,'Recursive':'true'})
with urllib.request.urlopen(url,timeout=20) as r: obj=json.load(r)
if not obj.get('Success'): raise SystemExit('model manifest request failed')
files=obj['Data']['Files']
print('pinned revision',rev,'files',len(files),'total_bytes',sum(x['Size'] for x in files if x['Type']=='blob'))
print('shard_1_sha256',next(x['Sha256'] for x in files if x['Name']=='model-00001-of-00005.safetensors'))
PY
