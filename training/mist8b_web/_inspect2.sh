#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
echo "== PROCS TREE =="
ps -eo pid,ppid,stat,etime,args | grep -E "download_model|download_qwen|relay|export_monitor|report_monitor|pipeline" | grep -v grep
echo "== PIDS =="
for f in download.pid qwen_download.pid pipeline.pid export_monitor.pid report_monitor.pid; do printf '%s=' "$f"; cat "$work/$f" 2>/dev/null; echo; done
echo "== TOKEN AUDIT SCRIPT =="
cat "$work"/audit_tokens_v2.py
echo "== TEMPLATE DEF =="
sed -n '1905,1945p' "$work"/env312/lib/python3.12/site-packages/llamafactory/data/template.py
echo "== LABEL COUNTS =="
"$work"/env312/bin/python - <<'PY'
import json,collections
p='/root/sj-tmp/cqsec_mist8b_web_20261115/data/web_fit_v2/train.jsonl'
c=collections.Counter(); s=collections.Counter()
for line in open(p,encoding='utf-8'):
    r=json.loads(line); c[r['_meta']['label']]+=1; s[r['_meta']['source']]+=1
print('labels',dict(c)); print('sources',dict(s)); print('total',sum(c.values()))
PY
