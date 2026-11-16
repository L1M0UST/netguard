#!/usr/bin/env bash
set -u
printf 'hostname: '
hostname
printf 'instance time: '
date -u '+%F %T UTC'
printf 'GPU: '
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
printf 'task dir: '
if [ -d /root/sj-tmp/cqsec_mist8b_web_20261115 ]; then echo exists; else echo missing; fi
if [ -e /root/sj-tmp/cqsec_mist8b_web_20261115/download.pid ]; then
  pid=$(cat /root/sj-tmp/cqsec_mist8b_web_20261115/download.pid)
  ps -p "$pid" -o pid,stat,args || true
fi
if [ -e /root/sj-tmp/cqsec_mist8b_web_20261115/models/MiST-8B/model.safetensors.partial ]; then
  stat -c 'partial_bytes=%s mtime=%y' /root/sj-tmp/cqsec_mist8b_web_20261115/models/MiST-8B/model.safetensors.partial
fi
df -h /root/sj-tmp
