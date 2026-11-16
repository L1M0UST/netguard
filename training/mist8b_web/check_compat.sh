#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
"$work/env312/bin/python" - "$work/models/MiST-8B-transformers4" <<'PY'
import sys
from transformers import AutoConfig
from llamafactory.data.template import get_template_and_fix_tokenizer
from llamafactory.hparams import DataArguments
from transformers import AutoTokenizer
path=sys.argv[1]
config=AutoConfig.from_pretrained(path,trust_remote_code=False,local_files_only=True)
tok=AutoTokenizer.from_pretrained(path,trust_remote_code=False,local_files_only=True)
args=DataArguments(template='qwen3_nothink',dataset='mist_web_train')
template=get_template_and_fix_tokenizer(tok,args)
messages=[{'role':'user','content':'hello 世界'},{'role':'assistant','content':'OK'}]
parts=template.encode_oneturn(tok,messages,system='',tools='')
print('architecture',type(config).__name__,'hidden',config.hidden_size,'layers',config.num_hidden_layers)
print('llamafactory_user_ids',parts[0])
expected=tok.encode('<|im_start|>user\nhello 世界<|im_end|>\n<|im_start|>assistant\n',add_special_tokens=False)
print('expected_user_ids',expected)
assert parts[0]==expected, 'LlamaFactory template differs from eval prompt'
print('TRAIN_EVAL_TEMPLATE_IDS_MATCH')
PY
