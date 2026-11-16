#!/usr/bin/env bash
set -euo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
test -f "$work/reports/qwen3_download.json"
test -f "$work/reports/token_audit_v2.json"
"$work/env312/bin/python" - <<'PY'
import json
from pathlib import Path
import yaml
from transformers import AutoTokenizer
from llamafactory.data.template import get_template_and_fix_tokenizer
from llamafactory.hparams import DataArguments
w=Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
model=w/'models/Qwen3-8B-ModelScope'
report=json.loads((w/'reports/qwen3_download.json').read_text())
assert report['all_files_sha256_verified'] and report['model_dir']==str(model)
for src,dest,run in [('smoke','qwen3_smoke','qwen3_smoke'),('profile','qwen3_profile','qwen3_profile'),('round1','qwen3_round1','qwen3_round1')]:
 target=w/'configs'/f'{dest}.yaml'
 if target.exists() or (w/'runs'/run).exists(): raise FileExistsError(str(target))
 cfg=yaml.safe_load((w/'configs'/f'{src}.yaml').read_text())
 cfg['model_name_or_path']=str(model)
 cfg['output_dir']=str(w/'runs'/run)
 target.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')
tok=AutoTokenizer.from_pretrained(model,local_files_only=True,trust_remote_code=False)
template=get_template_and_fix_tokenizer(tok,DataArguments(template='qwen3_nothink',dataset='mist_web_train'))
encoded=template.encode_oneturn(tok,[{'role':'user','content':'hello 世界'},{'role':'assistant','content':'OK'}],system='',tools='')[0]
expected=tok.encode('<|im_start|>user\nhello 世界<|im_end|>\n<|im_start|>assistant\n',add_special_tokens=False)
assert encoded==expected, 'Qwen training and evaluation templates differ'
print('Qwen3 configs prepared; training/evaluation prompt token IDs match')
PY
