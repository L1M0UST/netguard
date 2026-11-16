#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
free=$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits | head -1 | tr -d ' ')
if [ "$free" -lt 12000 ]; then echo 'skip tiny evaluator probe: less than 12 GiB free'; exit 2; fi
cd "$work"
export CUDA_VISIBLE_DEVICES=0 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false
timeout 180 /root/qwen3-vllm-085/bin/python - <<'PY'
import json,tempfile
from pathlib import Path
from vllm import LLM,SamplingParams
from vllm.lora.request import LoRARequest
import evaluate_qwen_vllm as e
import compare_qwen_vllm as c
root=Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
model=root/'models/probe-random-qwen3-v2';adapter=root/'runs/infra_probe_v2'
engine=LLM(model=str(model),dtype='bfloat16',max_model_len=256,gpu_memory_utilization=0.50,
           max_num_seqs=1,max_num_batched_tokens=256,enforce_eager=True,trust_remote_code=False,
           enable_lora=True,max_lora_rank=16,seed=42)
params=SamplingParams(temperature=0,max_tokens=8)
request=LoRARequest('random-test-adapter',1,str(adapter))
tok=engine.get_tokenizer()
ids=tok.encode('tiny probe',add_special_tokens=False)
rows=[{'record_id':str(i),'source':'synthetic','truth':'正常访问','input_tokens':len(ids),'prompt_ids':ids}
      for i in range(2)]
e.MODEL=model;e.ADAPTER=adapter;e.MAX_INPUT_TOKENS=128;e.MAX_NEW_TOKENS=8
with tempfile.TemporaryDirectory() as temp:
 e.REPORTS=Path(temp);c.REPORTS=Path(temp)
 e.evaluate(engine,params,rows,'qwen_vllm_official_baseline','official_nothink',None,'synthetic')
 e.evaluate(engine,params,rows,'qwen_vllm_official_adapter','official_nothink',request,'synthetic')
 result=c.compare('official')
 assert result['before']['samples']==result['after']['samples']==2
 assert set(result['before']['status_counts'])<= {'ok','unrecognized_output'}
 print('REAL_VLLM_EVALUATOR_AND_LORA_SMOKE_OK random model; not a model accuracy result')
PY
