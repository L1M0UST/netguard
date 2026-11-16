#!/usr/bin/env bash
set -euo pipefail
export CUDA_VISIBLE_DEVICES='' HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false
/root/qwen3-vllm-085/bin/python - <<'PY'
import inspect
from importlib.metadata import version
from transformers import AutoConfig,AutoTokenizer
from vllm import LLM,SamplingParams
from vllm.lora.request import LoRARequest
from vllm.model_executor.models.registry import ModelRegistry
model='/root/sj-tmp/cqsec_mist8b_web_20261115/models/Qwen3-8B-ModelScope'
cfg=AutoConfig.from_pretrained(model,local_files_only=True,trust_remote_code=False)
tok=AutoTokenizer.from_pretrained(model,local_files_only=True,trust_remote_code=False)
arch=cfg.architectures[0]
print('versions:',*[f'{x}={version(x)}' for x in ('vllm','torch','transformers','bitsandbytes')])
print('model architecture:',arch)
supported=ModelRegistry.get_supported_archs()
print('vllm architecture registered:',arch in supported)
assert arch in supported
p=tok.apply_chat_template([{'role':'user','content':'TEST'}],tokenize=False,
                           add_generation_prompt=True,enable_thinking=False)
assert p.endswith('<think>\n\n</think>\n\n')
print('official no-thinking template: verified')
print('generate accepts lora_request:', 'lora_request' in inspect.signature(LLM.generate).parameters)
assert 'lora_request' in inspect.signature(LLM.generate).parameters
assert SamplingParams(temperature=0,max_tokens=256).max_tokens==256
print('LoRARequest import:',LoRARequest.__name__)
print('CPU_IMPORT_ONLY_OK; real GPU inference has not been tested')
PY
