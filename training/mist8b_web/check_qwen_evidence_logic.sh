#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
export CUDA_VISIBLE_DEVICES=''
"$work/env312/bin/python" - <<'PY'
import json,tempfile
from pathlib import Path
import torch
from safetensors.torch import save_file
import preserve_qwen_checkpoints as p
import compare_qwen_vllm as c

with tempfile.TemporaryDirectory() as d:
 root=Path(d); source=root/'checkpoint-200'; source.mkdir()
 (source/'adapter_config.json').write_text(json.dumps({'r':16}))
 (source/'trainer_state.json').write_text(json.dumps({'global_step':200,'log_history':[{'step':200,'eval_loss':0.123}]}))
 save_file({'weight':torch.zeros(3)},str(source/'adapter_model.safetensors'))
 p.OUT=root/'saved';p.OUT.mkdir();p.REPORT=root/'checkpoints.json'
 assert p.capture(source)
 p.write_report()
 rep=json.loads(p.REPORT.read_text())
 assert rep['lowest_validation_loss_step']==200 and rep['candidates'][0]['eval_loss']==0.123
 assert not p.capture(source)
 print('checkpoint preservation self-check passed with synthetic CPU weights')

 c.REPORTS=root/'comparison';c.REPORTS.mkdir()
 settings={'data_sha256':'x','template':'official_nothink','max_input_tokens':2048,
           'max_new_tokens':256,'temperature':0.0,'engine_version':'0.8.5','base_precision':'bfloat16','samples':2}
 for name,preds in [('baseline',[('1','a','b'),('2','a','a')]),('adapter',[('1','a','a'),('2','a','b')])]:
  folder=c.REPORTS/f'qwen_vllm_official_{name}';folder.mkdir()
  (folder/'summary.json').write_text(json.dumps(settings))
  (folder/'predictions.jsonl').write_text(''.join(json.dumps({'record_id':i,'truth':t,'prediction':p})+'\n' for i,t,p in preds))
 result=c.compare('official')
 assert result['paired']=={'improved':1,'regressed':1}
 print('paired comparison self-check passed with synthetic predictions')
PY
