#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
export PIP_DEFAULT_TIMEOUT=120
export PIP_NO_CACHE_DIR=1
export TMPDIR="$work/tmp"
"$work/env312/bin/python" -m pip install 'pyarrow==19.0.1'
"$work/env312/bin/python" -m pip check
"$work/env312/bin/python" - <<'PY'
import numpy, pyarrow, datasets, torch
import llamafactory.data.template
print('numpy',numpy.__version__,'pyarrow',pyarrow.__version__,'datasets',datasets.__version__)
assert torch.cuda.is_available()
print('ENV_IMPORTS_VERIFIED')
PY
"$work/env312/bin/python" -m pip freeze > "$work/reports/environment312-verified-freeze.txt"
