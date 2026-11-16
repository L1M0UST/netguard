#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
"$work/env312/bin/python" - "$work" <<'PY'
import json,sys
from pathlib import Path
w=Path(sys.argv[1]);r=w/'runs/qwen3_round1/checkpoint-200/trainer_state.json'
if r.is_file():
 x=json.loads(r.read_text())
 print('checkpoint_200_global_step',x.get('global_step'))
 print('checkpoint_200_validation',[{'step':z.get('step'),'eval_loss':z.get('eval_loss')} for z in x.get('log_history',[]) if 'eval_loss' in z])
else:print('checkpoint_200_state_pending')
f=w/'reports/qwen_preserved_checkpoints.json'
if f.is_file():
 x=json.loads(f.read_text())
 print('preserved_candidates',[(c['step'],c['eval_loss']) for c in x.get('candidates',[])])
 print('lowest_validation_loss_step',x.get('lowest_validation_loss_step'))
print('checkpoint_monitor_state',(w/'reports/qwen_checkpoint_monitor_state.txt').read_text().strip())
PY
