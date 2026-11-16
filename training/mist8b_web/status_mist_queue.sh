#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'mist_queue_state='; cat "$work/reports/mist_after_qwen_state.txt"
pid=$(cat "$work/mist_after_qwen.pid")
ps -p "$pid" -o pid=,stat=,args=
printf 'verified_model='; cat "$work/reports/model-verified.txt"
