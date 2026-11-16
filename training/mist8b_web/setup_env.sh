#!/usr/bin/env bash
set -euo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
mkdir -p logs reports tmp cache/conda
export CONDA_PKGS_DIRS="$work/cache/conda"
export TMPDIR="$work/tmp"
export PIP_NO_CACHE_DIR=1
source /root/miniconda3/etc/profile.d/conda.sh
if [ ! -x "$work/env/bin/python" ]; then
    conda create --prefix "$work/env" python=3.11 pip -y
fi
py="$work/env/bin/python"
"$py" --version
"$py" -m pip install --upgrade 'pip<26' setuptools wheel
"$py" -m pip install torch==2.6.0 torchvision==0.21.0 torchaudio==2.6.0 --index-url https://download.pytorch.org/whl/cu124
"$py" -m pip install -c "$work/requirements-constraints.txt" 'llamafactory==0.9.4' 'bitsandbytes==0.45.5' 'datasketch==1.6.5'
"$py" -m pip check
"$py" -m pip freeze > "$work/reports/environment-freeze.txt"
"$py" - <<'PY'
import torch,transformers,peft,bitsandbytes
print('torch',torch.__version__,'CUDA',torch.version.cuda,'available',torch.cuda.is_available())
print('transformers',transformers.__version__,'peft',peft.__version__,'bitsandbytes',bitsandbytes.__version__)
assert torch.cuda.is_available()
assert torch.cuda.is_bf16_supported()
print('GPU',torch.cuda.get_device_name(0))
PY
printf 'ENV_SETUP_COMPLETED\n'
