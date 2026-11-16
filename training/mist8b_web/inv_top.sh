#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
echo "== HOST =="; hostname; date -u '+%F %T UTC'; uname -srm; nproc
echo "== MEM =="; free -g | head -3
echo "== GPU =="; nvidia-smi --query-gpu=name,driver_version,memory.total,memory.used,utilization.gpu,temperature.gpu,power.draw --format=csv,noheader
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader
echo "== DISK =="; df -h /root /root/sj-tmp
echo "== WORKDIR TOP =="; ls -la "$work" | head -45
echo "== MIST FILES =="; ls -la "$work"/models/MiST-8B/
echo "== DATA REPORT v4 =="; python3 - <<'PY'
import json
p='/root/sj-tmp/cqsec_mist8b_web_20261115/reports/data_report_v4.json'
d=json.load(open(p))
def walk(o,pre=''):
    if isinstance(o,dict):
        for k,v in o.items():
            if isinstance(v,(dict,list)) and k not in ('labels',): walk(v,pre+k+'.')
            else:
                s=str(v)
                print((pre+k)[:60],'=',s[:120])
walk(d)
PY
echo "== SAMPLE =="; head -c 1200 "$work"/data/web_fit_v2/train.jsonl
