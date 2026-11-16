#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf '%s\n' '--- Existing tiny-model infrastructure probe files ---'
find "$work/runs/infra_probe_v2" -maxdepth 2 -type f -printf '%s bytes\t%P\n' | sort -n | tail -n 20
printf '%s\n' '--- Compute expected target modules without loading model weights ---'
"$work/env312/bin/python" - "$work/models/MiST-8B/config.json" <<'PY'
import json,sys
import torch
from accelerate import init_empty_weights
from transformers import Qwen3Config,Qwen3ForCausalLM
from llamafactory.model.model_utils.misc import find_all_linear_modules
c=Qwen3Config(**json.load(open(sys.argv[1])))
with init_empty_weights():
 m=Qwen3ForCausalLM(c)
targets=find_all_linear_modules(m,freeze_vision_tower=False)
selected=[(n,x) for n,x in m.named_modules() if isinstance(x,torch.nn.Linear) and n.split('.')[-1] in targets]
rank=16
params=sum(rank*(layer.in_features+layer.out_features) for _,layer in selected)
print('target_names',sorted(targets))
print('linear_modules',len(selected))
print('lora_parameters_rank16',params)
print('adapter_fp32_gib',params*4/1024**3)
print('adapter_fp16_gib',params*2/1024**3)
print('estimated_adamw_two_fp32_moments_gib',params*8/1024**3)
print('estimated_fp32_adapter_plus_moments_gib',params*12/1024**3)
PY
