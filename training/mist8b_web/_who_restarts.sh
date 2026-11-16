#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
echo "== DOWNLOAD PROC TREE =="
ps -eo pid,ppid,pgid,stat,etime,args | grep -E "cqsec_mist8b_web|download_model|run_pipeline|monitor|resume|watch" | grep -v grep
echo "== PPID CHAIN =="
pid=16354
for i in 1 2 3 4 5; do
  line=$(ps -o pid=,ppid=,stat=,args= -p "$pid" 2>/dev/null) || break
  echo "$line"
  pid=$(echo "$line" | awk '{print $2}')
  [ "$pid" = "1" ] && break
done
echo "== CRONTAB =="
crontab -l 2>/dev/null || echo none
echo "== ALL BASH/PYTHON =="
ps -eo pid,ppid,stat,etime,args | awk '$NF ~ /\.sh|\.py/ || /cqsec/ {print}' | grep -v grep | head -40
echo "== SYSTEMD TIMERS =="
systemctl list-timers --all 2>/dev/null | head -10 || true
