#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
ls -ld "$work/models/probe-random-qwen3-v2" "$work/runs/infra_probe_v2" 2>/dev/null || true
tail -n 35 "$work/logs/infra_probe_v2.log" 2>/dev/null || true
ps -eo pid,ppid,stat,args | awk '/infra_probe_v2|llamafactory-cli/ && !/awk/ {print}'
