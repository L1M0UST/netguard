#!/usr/bin/env bash
set -euo pipefail
python - <<'PY'
import sys
import torch
print('python',sys.version.split()[0],sys.executable)
print('torch',torch.__version__,'CUDA build',torch.version.cuda)
print('cuda_available',torch.cuda.is_available(),'bf16',torch.cuda.is_bf16_supported())
print('torch_path',torch.__file__)
PY
df -h /root/sj-tmp
