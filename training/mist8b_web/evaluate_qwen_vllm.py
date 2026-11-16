"""Paired Qwen Web dev evaluation with vLLM, preserving every sample.

The primary comparison uses Qwen's official no-thinking chat template for both
the unadapted model and the LoRA adapter.  A smaller paired check uses the
exact prompt template used for SFT.  Neither uses the sealed test set.
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
import time
from importlib.metadata import version
from pathlib import Path

from evaluate_web import extract_label, metrics

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
DATA = WORK / 'data/web_fit_v2/dev.jsonl'
MODEL = WORK / 'models/Qwen3-8B-ModelScope'
ADAPTER = WORK / 'runs/qwen3_round1'
REPORTS = WORK / 'reports'
MAX_INPUT_TOKENS = 2048
MAX_NEW_TOKENS = 256
BATCH_SIZE = 40


def prompt_for(row: dict, tokenizer, mode: str) -> str:
    request = row.get('training_prompt') or row['instruction'] + '\n\n' + row['input']
    if mode == 'official_nothink':
        return tokenizer.apply_chat_template(
            [{'role': 'user', 'content': request}], tokenize=False,
            add_generation_prompt=True, enable_thinking=False,
        )
    if mode == 'sft_template':
        return '<|im_start|>user\n' + request + '<|im_end|>\n<|im_start|>assistant\n'
    raise ValueError(f'unknown template: {mode}')


def stratified_first(rows: list[dict], per_group: int = 5) -> list[dict]:
    counts = collections.Counter()
    result = []
    for row in rows:
        key = (row['_meta']['source'], row['_meta']['label'])
        if counts[key] < per_group:
            result.append(row)
            counts[key] += 1
    return result


def prepare(rows: list[dict], tokenizer, mode: str) -> list[dict]:
    prepared = []
    for row in rows:
        prompt = prompt_for(row, tokenizer, mode)
        ids = tokenizer.encode(prompt, add_special_tokens=False)
        meta = row['_meta']
        prepared.append({
            'record_id': meta['record_id'], 'source': meta['source'],
            'truth': meta['label'], 'input_tokens': len(ids), 'prompt_ids': ids,
        })
    return prepared


def evaluate(engine, sampling, prepared: list[dict], folder: str, mode: str,
             adapter_request, data_sha256: str) -> None:
    out = REPORTS / folder
    out.mkdir(parents=True, exist_ok=False)
    tick = time.monotonic()
    predictions = []
    with (out / 'predictions.jsonl').open('x', encoding='utf-8') as stream:
        for first in range(0, len(prepared), BATCH_SIZE):
            batch = prepared[first:first+BATCH_SIZE]
            valid = [r for r in batch if r['input_tokens'] <= MAX_INPUT_TOKENS]
            inputs = [{'prompt_token_ids': r['prompt_ids']} for r in valid]
            generated = engine.generate(inputs, sampling, lora_request=adapter_request,
                                        use_tqdm=False) if inputs else []
            if len(generated) != len(valid):
                raise RuntimeError('vLLM returned a different number of results')
            results = iter(generated)
            for row in batch:
                item = {k: row[k] for k in ('record_id', 'source', 'truth', 'input_tokens')}
                item.update(prediction='', status='input_too_long', output_tokens=0,
                            raw_output='', four_sections=False, finish_reason=None)
                if row['input_tokens'] <= MAX_INPUT_TOKENS:
                    output = next(results).outputs[0]
                    raw = output.text.strip()
                    pred = extract_label(raw)
                    item.update(
                        prediction=pred, status='ok' if pred else 'unrecognized_output',
                        output_tokens=len(output.token_ids), raw_output=raw,
                        four_sections=all('【' + s + '】' in raw for s in
                                          ('研判结论', '判定依据', 'ATT&CK映射', '处置建议')),
                        finish_reason=output.finish_reason,
                    )
                predictions.append(item)
                stream.write(json.dumps(item, ensure_ascii=False) + '\n')
            stream.flush()
            print(f'{folder}: {len(predictions)}/{len(prepared)} elapsed={time.monotonic()-tick:.1f}s', flush=True)
    summary = metrics(predictions)
    summary.update({
        'by_source': {s: metrics([r for r in predictions if r['source'] == s])
                      for s in sorted({r['source'] for r in predictions})},
        'data_sha256': data_sha256, 'model': str(MODEL),
        'adapter': str(ADAPTER) if adapter_request else None,
        'template': mode, 'max_input_tokens': MAX_INPUT_TOKENS,
        'max_new_tokens': MAX_NEW_TOKENS, 'temperature': 0.0,
        'engine': 'vLLM', 'engine_version': version('vllm'),
        'base_precision': 'bfloat16', 'training_precision': '4-bit NF4 QLoRA',
        'elapsed_seconds': time.monotonic() - tick,
        'finish_reason_counts': dict(collections.Counter(str(r['finish_reason']) for r in predictions)),
        'note': ('Development sample with source-derived labels, not independently audited; '
                 'not sealed-test or full-system acceptance performance.'),
    })
    temp = out / 'summary.json.tmp'
    temp.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    os.replace(temp, out / 'summary.json')
    print(f'{folder}: complete accuracy={summary["accuracy_all_samples"]:.4f} '
          f'macro_f1={summary["macro_f1_present_classes"]:.4f}', flush=True)


def main() -> None:
    os.environ.setdefault('HF_HUB_OFFLINE', '1')
    os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')
    os.environ.setdefault('TOKENIZERS_PARALLELISM', 'false')
    rows = [json.loads(line) for line in DATA.read_text(encoding='utf-8').splitlines() if line]
    assert len(rows) == 300, f'Unexpected dev sample size: {len(rows)}'
    assert len({r['_meta']['record_id'] for r in rows}) == len(rows), 'Duplicate record IDs'
    sha = hashlib.sha256(DATA.read_bytes()).hexdigest()
    expected = [f'qwen_vllm_{kind}_{which}' for kind in ('official', 'sftprompt')
                for which in ('baseline', 'adapter')]
    for name in expected:
        if (REPORTS / name).exists():
            raise FileExistsError(REPORTS / name)

    from transformers import AutoTokenizer
    from vllm import LLM, SamplingParams
    from vllm.lora.request import LoRARequest

    tokenizer = AutoTokenizer.from_pretrained(str(MODEL), local_files_only=True, trust_remote_code=False)
    primary = prepare(rows, tokenizer, 'official_nothink')
    auxiliary = prepare(stratified_first(rows), tokenizer, 'sft_template')
    print(f'loaded primary={len(primary)} template_check={len(auxiliary)}', flush=True)
    engine = LLM(model=str(MODEL), dtype='bfloat16', max_model_len=2304,
                 gpu_memory_utilization=0.85, max_num_seqs=4, max_num_batched_tokens=4096,
                 enforce_eager=True, trust_remote_code=False, enable_lora=True,
                 max_lora_rank=16, seed=42)
    sampling = SamplingParams(temperature=0.0, max_tokens=MAX_NEW_TOKENS,
                              skip_special_tokens=True)
    adapter = LoRARequest('qwen3_web_stage1', 1, str(ADAPTER))
    # Verify the real final adapter can be loaded before consuming time on the baseline.
    smoke = engine.generate([{'prompt_token_ids': primary[0]['prompt_ids']}], sampling,
                            lora_request=adapter, use_tqdm=False)
    assert len(smoke) == 1 and len(smoke[0].outputs) == 1
    print('vLLM real-adapter smoke passed', flush=True)
    for mode, prefix, dataset in [('official_nothink', 'official', primary),
                                   ('sft_template', 'sftprompt', auxiliary)]:
        evaluate(engine, sampling, dataset, f'qwen_vllm_{prefix}_baseline', mode, None, sha)
        evaluate(engine, sampling, dataset, f'qwen_vllm_{prefix}_adapter', mode, adapter, sha)


if __name__ == '__main__':
    main()
