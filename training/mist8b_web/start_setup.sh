set -eu
work=/root/sj-tmp/cqsec_mist8b_web_20261115
mkdir -p "$work/logs"
if [ -e "$work/setup.pid" ]; then
    printf '%s\n' 'setup.pid already exists; preserving the prior process and log'
    cat "$work/setup.pid"
    exit 1
fi
nohup bash "$work/setup_env.sh" > "$work/logs/setup_env.log" 2>&1 < /dev/null &
pid=$!
printf '%s\n' "$pid" > "$work/setup.pid"
printf 'ENV_SETUP_STARTED pid=%s\n' "$pid"
