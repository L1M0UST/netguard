set -eu
for url in \
 'https://hf-mirror.com/dreamgroup/MiST-8B/resolve/9ba377df00b9e830849fce8ebbe568a9a84774f2/config.json' \
 'https://hf-mirror.com/dreamgroup/MiST-8B/raw/9ba377df00b9e830849fce8ebbe568a9a84774f2/config.json' \
 'https://hf-mirror.com/dreamgroup/MiST-8B/resolve/9ba377df00b9e830849fce8ebbe568a9a84774f2/model.safetensors' \
 'https://huggingface.co/api/models/dreamgroup/MiST-8B/revision/9ba377df00b9e830849fce8ebbe568a9a84774f2'; do
  printf '\nURL %s\n' "$url"
  curl -sS -I --connect-timeout 8 --max-time 18 "$url" 2>&1 | head -n 12 || true
done
printf '\n=== Environment setup log ===\n'
tail -n 8 /root/sj-tmp/cqsec_mist8b_web_20261115/logs/setup_env.log || true
