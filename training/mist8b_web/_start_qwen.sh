#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
chmod +x run_qwen_stage1.sh qwen_stage1_status.sh
if [ -f "$work/qwen_stage1.pid" ] && kill -0 "$(cat "$work/qwen_stage1.pid")" 2>/dev/null; then
  echo "already running pid $(cat "$work/qwen_stage1.pid")"
else
  nohup bash "$work/run_qwen_stage1.sh" >> "$work/logs/qwen_stage1_runner.log" 2>&1 < /dev/null &
  echo $! > "$work/qwen_stage1.pid"
  echo "started pid $(cat "$work/qwen_stage1.pid")"
fi
sleep 3
cat "$work/reports/qwen_stage1_state.txt" 2>/dev/null || echo "(state file not yet written)"
ps -p "$(cat "$work/qwen_stage1.pid")" -o pid=,stat=,args= 2>/dev/null || echo "process missing"
df -h /root/sj-tmp | tail -1
