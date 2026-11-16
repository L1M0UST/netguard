#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
"$work/env312/bin/python" - "$work/models/probe-random-qwen3-v2" <<'PY'
import sys,torch,bitsandbytes as bnb
from transformers import AutoModelForCausalLM,BitsAndBytesConfig
q=BitsAndBytesConfig(load_in_4bit=True,bnb_4bit_quant_type='nf4',bnb_4bit_use_double_quant=True,bnb_4bit_compute_dtype=torch.bfloat16)
m=AutoModelForCausalLM.from_pretrained(sys.argv[1],local_files_only=True,quantization_config=q,device_map={'':0})
modules=[x for x in m.modules() if isinstance(x,bnb.nn.Linear4bit)]
assert modules
print('random Qwen3 loaded NF4 modules',len(modules),'double_quant',q.bnb_4bit_use_double_quant)
PY
