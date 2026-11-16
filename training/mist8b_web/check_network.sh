set -eu
for url in \
  https://hf-mirror.com/dreamgroup/MiST-8B/resolve/9ba377df00b9e830849fce8ebbe568a9a84774f2/config.json \
  https://hf-mirror.com/api/models/dreamgroup/MiST-8B/revision/9ba377df00b9e830849fce8ebbe568a9a84774f2 \
  https://download.pytorch.org/whl/cu124/torch/ \
  https://modelscope.cn/openapi/v1/models/dreamgroup/MiST-8B; do
    status=$(curl -L -sS -o /dev/null --connect-timeout 8 --max-time 18 -w '%{http_code}' "$url" 2>/dev/null || true)
    printf '%s %s\n' "$status" "$url"
done
printf '%s\n' '=== Existing directories ==='
ls -la /root/sj-tmp/cqsec_mist8b_web_20261115
