#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
"$work/env312/bin/python" - <<'PY'
import inspect
from llamafactory.model.model_utils.misc import find_all_linear_modules
print(inspect.signature(find_all_linear_modules))
print(inspect.getsource(find_all_linear_modules))
PY
