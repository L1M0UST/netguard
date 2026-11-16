"""Evaluate MiST Web classification using the system's M1 text contract.

All samples, including malformed and too-long requests, stay in denominators.
The balanced development sample is not a competition acceptance test.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import time
from pathlib import Path

LABELS = frozenset({
    'SQL注入攻击', 'XSS跨站脚本攻击', '目录遍历攻击', '文件包含攻击', '远程命令执行攻击',
    'CSRF攻击', 'Java反序列化漏洞利用攻击', '文件上传攻击', '暴力破解攻击', '扫描探测攻击',
    'Webshell通信攻击', 'C2回连攻击', 'SSRF攻击', 'XXE攻击', 'SSTI攻击', '正常访问',
})
LABEL_RE = re.compile(r'攻击类型[:：]\s*([^\n；;，,。]+)')
LABEL_FALLBACK_RE = re.compile(r'【研判结论】\s*([^\n；;，,。]+)')


def extract_label(text: str) -> str:
    match = LABEL_RE.search(text) or LABEL_FALLBACK_RE.search(text)
    value = match.group(1).strip() if match else ''
    if value and value not in LABELS:
        value = next((candidate for candidate in LABELS if candidate in value), '')
    return value


def metrics(rows: list[dict]) -> dict:
    classes = sorted({row['truth'] for row in rows})
    per_class = {}
    for label in classes:
        tp = sum(row['truth'] == label and row['prediction'] == label for row in rows)
        fp = sum(row['truth'] != label and row['prediction'] == label for row in rows)
        fn = sum(row['truth'] == label and row['prediction'] != label for row in rows)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        per_class[label] = {'support': tp + fn, 'tp': tp, 'fp': fp, 'fn': fn,
            'precision': precision, 'recall': recall,
            'f1': 2*precision*recall/(precision+recall) if precision+recall else 0.0}
    normal = [row for row in rows if row['truth'] == '正常访问']
    attacks = [row for row in rows if row['truth'] != '正常访问']
    return {
        'samples': len(rows),
        'accuracy_all_samples': sum(row['truth'] == row['prediction'] for row in rows) / max(len(rows), 1),
        'macro_f1_present_classes': sum(v['f1'] for v in per_class.values()) / max(len(classes), 1),
        'normal_flagged_attack_rate': sum(bool(r['prediction']) and r['prediction'] != '正常访问' for r in normal) / len(normal) if normal else None,
        'normal_unclassified_rate': sum(not r['prediction'] for r in normal) / len(normal) if normal else None,
        'attack_predicted_normal_rate': sum(r['prediction'] == '正常访问' for r in attacks) / len(attacks) if attacks else None,
        'four_sections_rate': sum(r['four_sections'] for r in rows) / len(rows) if rows else None,
        'status_counts': dict(collections.Counter(row['status'] for row in rows)),
        'per_class': per_class,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', required=True)
    parser.add_argument('--adapter')
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-input-tokens', type=int, default=2048)
    parser.add_argument('--max-new-tokens', type=int, default=256)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    rows = [json.loads(line) for line in args.data.read_text(encoding='utf-8').splitlines() if line]
    if not rows:
        raise ValueError('empty dataset')
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    assert torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    tokenizer = AutoTokenizer.from_pretrained(args.model, local_files_only=True, trust_remote_code=False)
    quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type='nf4',
                               bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.bfloat16)
    model = AutoModelForCausalLM.from_pretrained(args.model, local_files_only=True, trust_remote_code=False,
                                                  quantization_config=quant, device_map={'': 0})
    if args.adapter:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, args.adapter, is_trainable=False)
    model.eval()
    torch.cuda.reset_peak_memory_stats()
    predictions = []
    start = time.monotonic()
    with (args.output / 'predictions.jsonl').open('x', encoding='utf-8') as stream:
        for i, row in enumerate(rows, 1):
            request = row.get('training_prompt') or row['instruction'] + '\n\n' + row['input']
            # LlamaFactory qwen3_nothink: one user message, empty system prompt.
            prompt = '<|im_start|>user\n' + request + '<|im_end|>\n<|im_start|>assistant\n'
            batch = tokenizer(prompt, return_tensors='pt', add_special_tokens=False)
            n = int(batch['input_ids'].shape[-1])
            item = {'record_id': row['_meta']['record_id'], 'source': row['_meta']['source'],
                    'truth': row['_meta']['label'], 'prediction': '', 'status': 'invalid',
                    'input_tokens': n, 'output_tokens': 0, 'raw_output': '', 'four_sections': False}
            tick = time.monotonic()
            if n > args.max_input_tokens:
                item['status'] = 'input_too_long'
            else:
                try:
                    batch = {k: v.to('cuda:0') for k, v in batch.items()}
                    with torch.inference_mode():
                        output = model.generate(**batch, max_new_tokens=args.max_new_tokens, do_sample=False,
                                                pad_token_id=tokenizer.eos_token_id)
                    generated = output[0, n:]
                    text = tokenizer.decode(generated, skip_special_tokens=True).strip()
                    item['raw_output'] = text
                    item['output_tokens'] = int(generated.shape[0])
                    item['prediction'] = extract_label(text)
                    item['four_sections'] = all('【' + section + '】' in text
                        for section in ('研判结论', '判定依据', 'ATT&CK映射', '处置建议'))
                    item['status'] = 'ok' if item['prediction'] else 'unrecognized_output'
                except (ValueError, TypeError, RuntimeError) as exc:
                    item['status'] = 'inference_error:' + type(exc).__name__
            item['seconds'] = time.monotonic() - tick
            predictions.append(item)
            stream.write(json.dumps(item, ensure_ascii=False) + '\n')
            stream.flush()
            if i % 10 == 0 or i == len(rows):
                print(f'evaluated {i}/{len(rows)} in {time.monotonic()-start:.1f}s', flush=True)
    summary = metrics(predictions)
    summary.update({
        'by_source': {source: metrics([r for r in predictions if r['source'] == source])
                      for source in sorted({r['source'] for r in predictions})},
        'data_sha256': hashlib.sha256(args.data.read_bytes()).hexdigest(),
        'model': args.model, 'adapter': args.adapter, 'template': 'LlamaFactory qwen3_nothink',
        'max_input_tokens': args.max_input_tokens, 'max_new_tokens': args.max_new_tokens,
        'elapsed_seconds': time.monotonic() - start,
        'peak_cuda_gib': torch.cuda.max_memory_allocated() / 1024**3,
        'note': 'Balanced development sample; source labels are not independently verified; not a system acceptance test.',
    })
    (args.output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)


if __name__ == '__main__':
    main()
