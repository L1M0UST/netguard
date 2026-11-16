#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
bash -n "$work/wait_mist_after_qwen.sh"
export CUDA_VISIBLE_DEVICES='' HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false
/root/qwen3-vllm-085/bin/python - <<'PY'
import json
from pathlib import Path
from transformers import AutoConfig,AutoTokenizer
from vllm.model_executor.models.registry import ModelRegistry
import evaluate_mist_vllm as m
import evaluate_qwen_vllm as q
w=Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
model=m.MODEL
for name in ['COMPATIBILITY.json','config.json','tokenizer.json','tokenizer_config.json']:
 p=model/name
 assert p.is_file() and p.stat().st_size>0,name
tok=AutoTokenizer.from_pretrained(str(model),local_files_only=True,trust_remote_code=False)
cfg=AutoConfig.from_pretrained(str(model),local_files_only=True,trust_remote_code=False)
assert cfg.architectures[0] in ModelRegistry.get_supported_archs()
prompt=tok.apply_chat_template([{'role':'user','content':'TEST'}],tokenize=False,
                              add_generation_prompt=True,enable_thinking=False)
assert prompt.endswith('<think>\n\n</think>\n\n')
rows=[json.loads(s) for s in q.DATA.read_text(encoding='utf-8').splitlines() if s]
prepared=q.prepare(rows,tok,'official_nothink')
assert len(prepared)==300 and max(x['input_tokens'] for x in prepared)<=2048
print('MiST vLLM env CPU preflight passed; max dev prompt tokens',max(x['input_tokens'] for x in prepared))
print('Real MiST QLoRA and 8B vLLM inference remain untested')
PY
