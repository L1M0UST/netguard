#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
venv=/root/qwen3-vllm-085
state="$work/reports/vllm_install_state.txt"
trap 'code=$?; printf "failed exit=%s line=%s\n" "$code" "$LINENO" > "$state"; exit "$code"' ERR
test ! -e "$venv"
avail=$(df -Pk / | awk 'NR==2{print $4}')
test "$avail" -ge 15728640
printf 'creating_environment\n' > "$state"
/root/miniconda3/bin/python -m venv "$venv"
mkdir -p "$venv/tmp"
export TMPDIR="$venv/tmp" PIP_NO_CACHE_DIR=1 PIP_DEFAULT_TIMEOUT=120
printf 'installing_vllm\n' > "$state"
"$venv/bin/python" -m pip install --retries 8 'vllm==0.8.5' 'transformers==4.51.3' 'bitsandbytes==0.45.5'
"$venv/bin/python" -m pip check
"$venv/bin/python" -m pip freeze > "$work/reports/vllm_environment_freeze.txt"
"$venv/bin/python" - <<'PY'
from importlib.metadata import version
for name in ('vllm','torch','transformers','bitsandbytes'):
 print(name,version(name))
PY
printf 'installed_untested\n' > "$state"
printf 'VLLM_ENVIRONMENT_INSTALLED\n'
