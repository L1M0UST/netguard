"""Audit context limits and derive a training split that fits without truncation."""
from __future__ import annotations

import collections
import hashlib
import json
from pathlib import Path

from transformers import AutoTokenizer

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
SOURCE = WORK / 'data/web_v4'
TARGET = WORK / 'data/web_fit_v2'
MODEL = WORK / 'models/MiST-8B-transformers4'
LIMIT = 2032  # 16-token headroom below the configured cutoff of 2048.


def main() -> None:
    TARGET.mkdir(parents=True, exist_ok=False)
    tokenizer = AutoTokenizer.from_pretrained(MODEL, local_files_only=True, trust_remote_code=False)
    counters = collections.Counter()
    kept = collections.Counter()
    too_long = collections.Counter()
    total_tokens = 0
    maximum = 0
    with (SOURCE / 'train.jsonl').open(encoding='utf-8') as inp, \
         (TARGET / 'train.jsonl').open('x', encoding='utf-8') as out:
        for index, line in enumerate(inp, 1):
            row = json.loads(line)
            prompt = row['training_prompt']
            assert prompt == row['instruction'] + '\n\n' + row['input'] and row['blank_query'] == ''
            text = '<|im_start|>user\n' + prompt + '<|im_end|>\n<|im_start|>assistant\n' + row['output'] + '<|im_end|>\n'
            length = len(tokenizer.encode(text, add_special_tokens=False))
            key = row['_meta']['source'] + '/' + row['_meta']['label']
            counters[key] += 1
            total_tokens += length
            maximum = max(maximum, length)
            if length <= LIMIT:
                kept[key] += 1
                out.write(line)
            else:
                too_long[key] += 1
            if index % 5000 == 0:
                print('tokenized', index, 'excluded', sum(too_long.values()), flush=True)
    # Keep all validation cases; too-long inputs are explicitly counted by eval.
    (TARGET / 'dev.jsonl').write_bytes((SOURCE / 'dev.jsonl').read_bytes())
    info = json.loads((SOURCE / 'dataset_info.json').read_text(encoding='utf-8'))
    (TARGET / 'dataset_info.json').write_text(json.dumps(info, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    report = {'cutoff': 2048, 'headroom': 16, 'source_train': sum(counters.values()),
        'kept_train': sum(kept.values()), 'excluded_long_train': sum(too_long.values()),
        'max_tokens_before_filter': maximum, 'mean_tokens_before_filter': total_tokens / max(sum(counters.values()), 1),
        'before_by_source_label': dict(counters), 'kept_by_source_label': dict(kept),
        'excluded_by_source_label': dict(too_long),
        'train_sha256': hashlib.sha256((TARGET / 'train.jsonl').read_bytes()).hexdigest()}
    (WORK / 'reports/token_audit_v2.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)


if __name__ == '__main__':
    main()
