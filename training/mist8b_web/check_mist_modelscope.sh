#!/usr/bin/env bash
set -u
python - <<'PY'
import json, urllib.error, urllib.request
for repo in ('dreamgroup/MiST-8B','AI-ModelScope/MiST-8B'):
 try:
  with urllib.request.urlopen('https://www.modelscope.cn/api/v1/models/'+repo,timeout=15) as r:
   obj=json.load(r)
  data=obj.get('Data') or {}
  print(repo,'success',obj.get('Success'),'model_name',data.get('Name'))
 except urllib.error.HTTPError as exc:
  print(repo,'http_status',exc.code)
 except Exception as exc:
  print(repo,type(exc).__name__)
PY
