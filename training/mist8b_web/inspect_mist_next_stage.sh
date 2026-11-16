#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
"$work/env312/bin/python" - "$work" <<'PY'
import json,sys,yaml
from pathlib import Path
from transformers import AutoConfig,AutoTokenizer
w=Path(sys.argv[1])
for name in ('smoke','round1'):
 p=w/'configs'/f'{name}.yaml'
 print('CONFIG',name, yaml.safe_load(p.read_text()))
for name in ('token_audit_v2.json','model-verified.txt','pipeline-state.txt'):
 p=w/'reports'/name
 print('REPORT',name,p.read_text()[:1200] if p.exists() else 'missing')
for name in ('smoke','round1'):
 print('RUN_EXISTS',name,(w/'runs'/name).exists())
model=w/'models/MiST-8B-transformers4'
c=AutoConfig.from_pretrained(model,local_files_only=True,trust_remote_code=False)
t=AutoTokenizer.from_pretrained(model,local_files_only=True,trust_remote_code=False)
print('MIST_ARCH',c.model_type,c.architectures,c.hidden_size,c.num_hidden_layers)
print('MIST_TOKENIZER',len(t),'nothink_suffix',repr(t.apply_chat_template([{'role':'user','content':'TEST'}],tokenize=False,add_generation_prompt=True,enable_thinking=False)[-100:]))
PY
