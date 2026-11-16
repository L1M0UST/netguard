#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'time_utc='; date -u '+%F %T'
echo "== DISK =="; df -h / /root/sj-tmp | tail -2
echo "== GPU =="; nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu,temperature.gpu,power.draw --format=csv,noheader
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader
echo "== PROCS =="
ps -eo pid,ppid,stat,etime,args | grep -E "cqsec_mist8b_web|download_model|run_pipeline|monitor|llamafactory|python.*train" | grep -v grep
echo "== PIDS =="
for f in download.pid pipeline.pid qwen_download.pid report_monitor.pid export_monitor.pid; do printf '%s=' "$f"; cat "$work/$f" 2>/dev/null; echo; done
echo "== STATE =="
cat "$work/reports/pipeline-state.txt" 2>/dev/null || echo "(no pipeline-state)"
cat "$work/reports/qwen_stage1_state.txt" 2>/dev/null || echo "(no qwen state)"
echo "== MIST BYTES =="
python3 - <<'PY'
from pathlib import Path
w=Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
p=w/'models/MiST-8B/model.safetensors.partial'; f=w/'models/MiST-8B/model.safetensors'
print('mist_bytes', f.stat().st_size if f.exists() else p.stat().st_size if p.exists() else 0, 'of 16381517208')
PY
echo "== MIST LOG TAIL =="; tail -n 6 "$work/logs/download_model.log" 2>/dev/null
echo "== RUNS =="; find "$work/runs" -maxdepth 2 -name "*.json" -newermt '-2 hours' 2>/dev/null | head
du -sh "$work"/runs/* 2>/dev/null
echo "== ADAPTER CHECK =="; ls -la "$work"/runs/round1 2>/dev/null | head
