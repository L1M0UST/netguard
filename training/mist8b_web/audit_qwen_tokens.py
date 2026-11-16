"""Audit Web SFT token lengths with the actual Qwen3 tokenizer and template.

Read-only: reports lengths, does not rewrite the dataset. The training text is
assembled exactly as LLaMA-Factory's qwen3_nothink template does for one user turn.
"""
from __future__ import annotations

import collections
import hashlib
import json
from pathlib import Path

from transformers import AutoTokenizer

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
TRAIN = WORK / 'data/web_fit_v2/train.jsonl'
DEV = WORK / 'data/web_fit_v2/dev.jsonl'
MODEL = WORK / 'models/Qwen3-8B-ModelScope'
CUTOFF = 2048


def training_text(row: dict) -> str:
    return ('<|im_start|>user\n' + row['training_prompt'] + '<|im_end|>\n'
            '<|im_start|>assistant\n' + row['output'] + '<|im_end|>\n')


def eval_text(row: dict) -> str:
    return '<|im_start|>user\n' + row['training_prompt'] + '<|im_end|>\n<|im_start|>assistant\n'


def stats(lengths: list[int]) -> dict:
    ordered = sorted(lengths)
    return {
        'count': len(ordered),
        'max': ordered[-1] if ordered else 0,
        'mean': sum(ordered) / len(ordered) if ordered else 0.0,
        'p95': ordered[int(len(ordered) * 0.95)] if ordered else 0,
        'p99': ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))] if ordered else 0,
        'over_cutoff': sum(length > CUTOFF for length in ordered),
        'near_limit_2032_2048': sum(2032 < length <= CUTOFF for length in ordered),
    }


def main() -> None:
    tokenizer = AutoTokenizer.from_pretrained(MODEL, local_files_only=True, trust_remote_code=False)
    train_lengths: list[int] = []
    dev_lengths: list[int] = []
    per_source: dict[str, list[int]] = collections.defaultdict(list)
    over: list[dict] = []
    with TRAIN.open(encoding='utf-8') as stream:
        for index, line in enumerate(stream, 1):
            row = json.loads(line)
            length = len(tokenizer.encode(training_text(row), add_special_tokens=False))
            train_lengths.append(length)
            per_source[row['_meta']['source']].append(length)
            if length > CUTOFF:
                over.append({'record_id': row['_meta']['record_id'],
                             'source': row['_meta']['source'],
                             'label': row['_meta']['label'],
                             'tokens': length})
            if index % 10000 == 0:
                print('tokenized', index, flush=True)
    with DEV.open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            dev_lengths.append(len(tokenizer.encode(eval_text(row), add_special_tokens=False)))
    report = {
        'tokenizer': 'Qwen/Qwen3-8B ModelScope',
        'template': 'llamafactory qwen3_nothink (single user turn)',
        'cutoff_len': CUTOFF,
        'train_text_sha256': hashlib.sha256(TRAIN.read_bytes()).hexdigest(),
        'train': stats(train_lengths),
        'dev_prompt': stats(dev_lengths),
        'by_source': {name: stats(values) for name, values in sorted(per_source.items())},
        'over_cutoff_records': over[:200],
        'over_cutoff_total': len(over),
        'note': 'Lengths include the assistant answer and <|im_end|>; LLaMA-Factory may drop or truncate over-cutoff rows depending on truncation_strategy.',
    }
    (WORK / 'reports/qwen_token_audit.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in report.items() if k != 'over_cutoff_records'},
                     ensure_ascii=False, indent=2), flush=True)


if __name__ == '__main__':
    main()
