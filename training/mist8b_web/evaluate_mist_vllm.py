"""Evaluate MiST base and its own LoRA on the same Web dev samples with vLLM."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import evaluate_qwen_vllm as common

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
MODEL = WORK / 'models/MiST-8B-transformers4'
ADAPTER = WORK / 'runs/round1'
REPORTS = WORK / 'reports'


def main() -> None:
    os.environ.setdefault('HF_HUB_OFFLINE', '1')
    os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')
    os.environ.setdefault('TOKENIZERS_PARALLELISM', 'false')
    rows = [json.loads(s) for s in common.DATA.read_text(encoding='utf-8').splitlines() if s]
    assert len(rows) == 300 and len({r['_meta']['record_id'] for r in rows}) == 300
    sha = hashlib.sha256(common.DATA.read_bytes()).hexdigest()
    for template in ('official', 'sftprompt'):
        for variant in ('baseline', 'adapter'):
            if (REPORTS / f'mist_vllm_{template}_{variant}').exists():
                raise FileExistsError(REPORTS / f'mist_vllm_{template}_{variant}')
    from transformers import AutoTokenizer
    from vllm import LLM, SamplingParams
    from vllm.lora.request import LoRARequest

    # Shared implementation keeps prompts, decoding, parsing and metrics aligned with Qwen.
    common.MODEL = MODEL
    common.ADAPTER = ADAPTER
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL), local_files_only=True, trust_remote_code=False)
    primary = common.prepare(rows, tokenizer, 'official_nothink')
    auxiliary = common.prepare(common.stratified_first(rows), tokenizer, 'sft_template')
    print('MiST paired datasets:', len(primary), len(auxiliary), flush=True)
    engine = LLM(model=str(MODEL), dtype='bfloat16', max_model_len=2304,
                 gpu_memory_utilization=0.85, max_num_seqs=4, max_num_batched_tokens=4096,
                 enforce_eager=True, trust_remote_code=False, enable_lora=True,
                 max_lora_rank=16, seed=42)
    sampling = SamplingParams(temperature=0.0, max_tokens=common.MAX_NEW_TOKENS,
                              skip_special_tokens=True)
    adapter = LoRARequest('mist8b_web_stage1', 1, str(ADAPTER))
    smoke = engine.generate([{'prompt_token_ids': primary[0]['prompt_ids']}], sampling,
                            lora_request=adapter, use_tqdm=False)
    assert len(smoke) == 1 and len(smoke[0].outputs) == 1
    print('vLLM real MiST adapter smoke passed', flush=True)
    for mode, prefix, dataset in [('official_nothink', 'official', primary),
                                   ('sft_template', 'sftprompt', auxiliary)]:
        common.evaluate(engine, sampling, dataset, f'mist_vllm_{prefix}_baseline', mode, None, sha)
        common.evaluate(engine, sampling, dataset, f'mist_vllm_{prefix}_adapter', mode, adapter, sha)


if __name__ == '__main__':
    main()
