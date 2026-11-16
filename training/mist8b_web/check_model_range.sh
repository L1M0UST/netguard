set -u
url='https://hf-mirror.com/dreamgroup/MiST-8B/resolve/9ba377df00b9e830849fce8ebbe568a9a84774f2/model.safetensors'
printf '%s\n' 'Checking model download through mirror (first byte only)...'
for i in 1 2 3; do
  status=$(curl -L -sS -o /dev/null -r 0-0 --connect-timeout 10 --max-time 25 -w '%{http_code} bytes=%{size_download} speed=%{speed_download}' "$url" 2>/dev/null || true)
  printf 'attempt=%s %s\n' "$i" "$status"
  case "$status" in 206\ *) break;; esac
done
printf '%s\n' '=== Environment progress ==='
tail -n 8 /root/sj-tmp/cqsec_mist8b_web_20261115/logs/setup_env.log || true
