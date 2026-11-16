set -eu
printf '%s\n' '=== GPU ==='
nvidia-smi --query-gpu=name,memory.total,memory.free,driver_version --format=csv,noheader,nounits
printf '%s\n' '=== CPU and memory quota ==='
getconf _NPROCESSORS_ONLN
for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes; do
    if [ -r "$f" ]; then printf '%s: ' "$f"; cat "$f"; fi
done
printf '%s\n' '=== Storage ==='
df -h / /root/sj-tmp /root/sj-fs
printf '%s\n' '=== Python environment ==='
python --version
conda --version
python - <<'PY'
import torch
print('torch:', torch.__version__, 'torch CUDA:', torch.version.cuda)
print('CUDA available:', torch.cuda.is_available())
print('BF16 supported:', torch.cuda.is_bf16_supported() if torch.cuda.is_available() else False)
PY
printf '%s\n' '=== Network reachability ==='
for url in https://huggingface.co/dreamgroup/MiST-8B/resolve/9ba377df00b9e830849fce8ebbe568a9a84774f2/config.json https://pypi.org/simple/transformers/ https://repo.anaconda.com/pkgs/main/; do
    result=$(curl -L -sS -o /dev/null --connect-timeout 8 --max-time 15 -w '%{http_code}' "$url" 2>/dev/null || true)
    printf '%s %s\n' "$result" "$url"
done
printf '%s\n' '=== Working directory ==='
if [ -e /root/sj-tmp/cqsec_mist8b_web_20261115 ]; then
    printf '%s\n' 'already exists; preserving existing contents'
    ls -ld /root/sj-tmp/cqsec_mist8b_web_20261115
else
    umask 077
    mkdir -p /root/sj-tmp/cqsec_mist8b_web_20261115
    printf '%s\n' 'created new isolated work directory on data disk'
fi
