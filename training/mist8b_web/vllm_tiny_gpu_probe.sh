#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
free=$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits | head -1 | tr -d ' ')
if [ "$free" -lt 12000 ]; then echo 'skip tiny probe: less than 12 GiB free'; exit 2; fi
export CUDA_VISIBLE_DEVICES=0 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false
timeout 180 /root/qwen3-vllm-085/bin/python - <<'PY'
from vllm import LLM,SamplingParams
from vllm.lora.request import LoRARequest
root='/root/sj-tmp/cqsec_mist8b_web_20261115'
engine=LLM(model=root+'/models/probe-random-qwen3-v2',dtype='bfloat16',max_model_len=256,
           gpu_memory_utilization=0.50,max_num_seqs=1,max_num_batched_tokens=256,
           enforce_eager=True,trust_remote_code=False,enable_lora=True,max_lora_rank=16,seed=42)
params=SamplingParams(temperature=0,max_tokens=8)
adapter=LoRARequest('random-test-adapter',1,root+'/runs/infra_probe_v2')
base=engine.generate(['test'],params,use_tqdm=False)
tuned=engine.generate(['test'],params,lora_request=adapter,use_tqdm=False)
assert len(base)==len(tuned)==1 and len(base[0].outputs)==len(tuned[0].outputs)==1
assert len(base[0].outputs[0].token_ids)>0 and len(tuned[0].outputs[0].token_ids)>0
print('VLLM_TINY_GPU_BASE_AND_LORA_OK (random model, not real Qwen accuracy)')
PY
