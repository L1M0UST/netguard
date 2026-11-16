#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'installation state: '; cat "$work/reports/vllm_install_state.txt" 2>/dev/null
printf '\nresolver messages:\n'
rg -i 'looking at multiple|backtrack|conflict|error|incompatible|requires|will take' "$work/logs/vllm_install.log" | tail -35 || true
printf '\nlatest messages:\n'
tail -16 "$work/logs/vllm_install.log"
printf '\nspace:\n'
df -h / /root/sj-tmp | tail -2
