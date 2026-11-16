#!/usr/bin/env bash
set -euo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
export TMPDIR="$work/tmp"
export PIP_NO_CACHE_DIR=1
export PIP_DEFAULT_TIMEOUT=120
mkdir -p "$TMPDIR" logs reports
python -m venv --system-site-packages "$work/env312"
py="$work/env312/bin/python"
"$py" -m pip install --upgrade 'pip<26' setuptools wheel
"$py" -m pip install \
  'llamafactory==0.9.4' 'transformers==4.53.3' 'datasets==3.6.0' \
  'accelerate==1.8.1' 'peft==0.16.0' 'trl==0.19.1' 'bitsandbytes==0.45.5' \
  'huggingface-hub==0.34.4' 'numpy<2' 'datasketch==1.6.5'
"$py" -m pip check
"$py" -m pip freeze > "$work/reports/environment312-freeze.txt"
"$py" - <<'PY'
import sys,torch,transformers,peft,bitsandbytes
print('python',sys.version.split()[0])
print('torch',torch.__version__,'CUDA',torch.version.cuda,'available',torch.cuda.is_available())
print('transformers',transformers.__version__,'peft',peft.__version__,'bitsandbytes',bitsandbytes.__version__)
assert torch.cuda.is_available() and torch.cuda.is_bf16_supported()
print('GPU',torch.cuda.get_device_name(0))
PY
printf 'ENV312_SETUP_COMPLETED\n'
