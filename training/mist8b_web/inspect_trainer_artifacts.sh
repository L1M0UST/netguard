#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
"$work/env312/bin/python" - "$work" <<'PY'
import json,sys
from pathlib import Path
w=Path(sys.argv[1])
for root in [w/'runs/qwen3_smoke',w/'runs/qwen3_round1']:
 print('RUN',root.name)
 print('entries',[p.name for p in root.iterdir() if p.is_dir() or p.suffix in ('.json','.jsonl')])
 for f in sorted(root.glob('checkpoint-*/trainer_state.json'))[:2]+[root/'trainer_state.json']:
  if f.is_file():
   x=json.loads(f.read_text());print('state',str(f.relative_to(root)),'global_step',x.get('global_step'),'evals',[(z.get('step'),z.get('eval_loss')) for z in x.get('log_history',[]) if 'eval_loss' in z])
PY
