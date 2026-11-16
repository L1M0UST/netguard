set -u
printf '%s\n' '=== downloader availability ==='
command -v aria2c || true
printf '%s\n' '=== model range transfer sample ==='
url='https://hf-mirror.com/dreamgroup/MiST-8B/resolve/9ba377df00b9e830849fce8ebbe568a9a84774f2/model.safetensors'
curl -LsS -o /dev/null -r 0-16777215 --connect-timeout 15 --max-time 60 \
  -w 'HTTP=%{http_code} bytes=%{size_download} seconds=%{time_total} bytes_per_second=%{speed_download}\n' "$url" 2>/dev/null || true
printf '%s\n' '=== current byte counts ==='
stat -c '%n %s' /root/sj-tmp/cqsec_mist8b_web_20261115/models/MiST-8B/model.safetensors.partial 2>/dev/null || true
printf '%s\n' '=== setup state ==='
tail -n 3 /root/sj-tmp/cqsec_mist8b_web_20261115/logs/setup_env.log || true
