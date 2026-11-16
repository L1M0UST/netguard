#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
"$work/env312/bin/python" - <<'PY'
import inspect
from llamafactory.data.template import get_template_and_fix_tokenizer
from llamafactory.hparams import DataArguments
from transformers import AutoTokenizer
path='/root/sj-tmp/cqsec_mist8b_web_20261115/models/Qwen3-8B-ModelScope'
tok=AutoTokenizer.from_pretrained(path,local_files_only=True)
tmpl=get_template_and_fix_tokenizer(tok, DataArguments(template='qwen3_nothink'))
messages=[{'role':'user','content':'TEST_USER'},{'role':'assistant','content':'TEST_ANSWER'}]
prompt_ids,response_ids=tmpl.encode_oneturn(tok,messages,system=None,tools=None)
print('LLAMAFACTORY_PROMPT=',repr(tok.decode(prompt_ids)))
print('LLAMAFACTORY_RESPONSE=',repr(tok.decode(response_ids)))
print('QWEN_OFFICIAL_NOTHINK=',repr(tok.apply_chat_template(messages[:1],tokenize=False,add_generation_prompt=True,enable_thinking=False)))
print('VLLM_EVAL_PROMPT=',repr('<|im_start|>user\nTEST_USER<|im_end|>\n<|im_start|>assistant\n'))
PY
