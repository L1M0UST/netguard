#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf 'host='; hostname
df -h /root/sj-tmp
python - <<'PY'
import importlib.util
print('modelscope_available',bool(importlib.util.find_spec('modelscope')))
PY
url='https://www.modelscope.cn/api/v1/models/Qwen/Qwen3-8B/repo?Revision=master&FilePath=model-00001-of-00005.safetensors'
printf 'ModelScope official first shard range test (32 MiB)\n'
curl -fsSL --connect-timeout 15 --max-time 80 --max-filesize 33554432 \
  -r 0-33554431 -o /dev/null \
  -w 'http_status=%{http_code} downloaded_bytes=%{size_download} seconds=%{time_total} bytes_per_second=%{speed_download}\n' "$url"
