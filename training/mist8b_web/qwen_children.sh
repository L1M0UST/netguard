#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
pid=$(cat "$work/qwen_download.pid")
ps -p "$pid" -o pid=,ppid=,stat=,args=
ps -eo pid,ppid,stat,args | awk -v p="$pid" '$2==p {print}'
tail -n 8 "$work/logs/qwen_download.log"
