#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
echo "== BEFORE =="
ps -eo pid,ppid,stat,args | grep -E "download_model|run_pipeline_v2|report_monitor|export_monitor" | grep -v grep
# kill children of download_model.sh first, then the shell
for pid in 461 1650 2416 2778; do
  if kill -0 "$pid" 2>/dev/null; then
    pkill -TERM -P "$pid" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true
  fi
done
sleep 3
for pid in 461 1650 2416 2778; do kill -KILL "$pid" 2>/dev/null || true; done
sleep 1
echo "== AFTER =="
ps -eo pid,ppid,stat,args | grep -E "download_model|run_pipeline_v2|report_monitor|export_monitor" | grep -v grep || echo "old jobs stopped"
echo "== MIST PARTIAL KEPT =="
ls -lh "$work"/models/MiST-8B/model.safetensors.partial 2>/dev/null
echo "== GPU =="
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader || true
df -h /root/sj-tmp | tail -1
