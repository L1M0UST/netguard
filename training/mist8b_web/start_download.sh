set -eu
work=/root/sj-tmp/cqsec_mist8b_web_20261115
mkdir -p "$work/logs"
if [ -e "$work/download.pid" ]; then
    printf '%s\n' 'download.pid already exists; preserving prior process and log'
    cat "$work/download.pid"
    exit 1
fi
nohup bash "$work/download_model.sh" > "$work/logs/download_model.log" 2>&1 < /dev/null &
pid=$!
printf '%s\n' "$pid" > "$work/download.pid"
printf 'MODEL_DOWNLOAD_STARTED pid=%s\n' "$pid"
