#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
echo "== KILL =="
pkill -TERM -f 'run_pipeline_v2.sh' 2>/dev/null || true
pkill -TERM -f 'report_monitor.sh' 2>/dev/null || true
pkill -TERM -f 'export_monitor.sh' 2>/dev/null || true
pkill -TERM -f 'download_model.sh' 2>/dev/null || true
pkill -TERM -f 'model.safetensors.partial' 2>/dev/null || true
sleep 3
pkill -KILL -f 'run_pipeline_v2.sh' 2>/dev/null || true
pkill -KILL -f 'report_monitor.sh' 2>/dev/null || true
pkill -KILL -f 'export_monitor.sh' 2>/dev/null || true
pkill -KILL -f 'download_model.sh' 2>/dev/null || true
pkill -KILL -f 'model.safetensors.partial' 2>/dev/null || true
sleep 1
ps -eo pid,ppid,stat,args | grep -E "download_model|run_pipeline|monitor|safetensors.partial" | grep -v grep || echo "all stopped"
echo "== GPU =="; nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader || true
echo "== PARTIAL KEPT =="
ls -lh "$work"/models/MiST-8B/model.safetensors.partial 2>/dev/null
echo "== AUTOSTART SOURCES =="
echo "-- rc.local:"; cat /etc/rc.local 2>/dev/null || echo none
echo "-- crontab:"; crontab -l 2>/dev/null || echo none
echo "-- /etc/cron*:"; grep -rl "cqsec_mist8b_web\|run_pipeline\|download_model" /etc/cron* /etc/crontab 2>/dev/null || echo none
echo "-- supervisor:"; ls /etc/supervisor/conf.d/ 2>/dev/null; grep -rl "cqsec_mist8b_web\|run_pipeline\|download_model" /etc/supervisor 2>/dev/null || true
echo "-- profile.d:"; grep -rl "cqsec_mist8b_web\|run_pipeline\|download_model" /etc/profile.d/ /root/.bashrc /root/.profile 2>/dev/null || true
echo "-- systemd:"; grep -rl "cqsec_mist8b_web\|run_pipeline\|download_model" /etc/systemd/system/ 2>/dev/null || true
