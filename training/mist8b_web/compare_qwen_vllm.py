"""Compare paired vLLM Web dev predictions, including a prompt-template check."""
from __future__ import annotations

import json
from pathlib import Path

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
REPORTS = WORK / 'reports'


def load(name: str):
    directory = REPORTS / name
    summary = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
    predictions = [json.loads(line) for line in
                   (directory / 'predictions.jsonl').read_text(encoding='utf-8').splitlines() if line]
    assert summary['samples'] == len(predictions)
    return summary, predictions


def compare(prefix: str) -> dict:
    before, base = load(f'qwen_vllm_{prefix}_baseline')
    after, tuned = load(f'qwen_vllm_{prefix}_adapter')
    for key in ('data_sha256', 'template', 'max_input_tokens', 'max_new_tokens',
                'temperature', 'engine_version', 'base_precision'):
        assert before[key] == after[key], f'comparison setting differs: {key}'
    assert [(p['record_id'], p['truth']) for p in base] == [(p['record_id'], p['truth']) for p in tuned]
    return {
        'before': before, 'after': after,
        'paired': {
            'improved': sum(a['prediction'] != a['truth'] and b['prediction'] == b['truth']
                            for a, b in zip(base, tuned)),
            'regressed': sum(a['prediction'] == a['truth'] and b['prediction'] != b['truth']
                             for a, b in zip(base, tuned)),
        },
    }


def pct(value):
    return '--' if value is None else f'{100*value:.2f}%'


def main() -> None:
    report = {
        'model': 'Qwen/Qwen3-8B ModelScope, revision 26028140be3ee69b82b1d1450179ab71bb1121b9',
        'primary_official_nothink': compare('official'),
        'supplementary_sft_template': compare('sftprompt'),
        'interpretation': ('Development set only, with source-derived labels; not sealed-test '
                           'or end-to-end system performance. Training used NF4 QLoRA; '
                           'both sides of each inference comparison use the same BF16 base.'),
    }
    path_json = REPORTS / 'qwen_vllm_comparison.json'
    path_md = REPORTS / 'qwen_vllm_comparison.md'
    if path_json.exists() or path_md.exists():
        raise FileExistsError('comparison report already exists')
    with path_json.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    lines = ['# Qwen3-8B 第一轮 Web 研判：vLLM 验证集对比', '',
             '主对比使用相同的 Qwen 官方关闭思考模板；补充对比使用训练时的模板。',
             '两侧均为 vLLM BF16 推理，微调本身采用 NF4 QLoRA。验证集按来源和类别均衡，',
             '标签来自数据源、未逐条人工复核；它不是封存测试或完整系统验收结果。']
    for title, key in [('主对比：官方关闭思考模板', 'primary_official_nothink'),
                       ('补充对比：训练时模板（每来源/类别最多 5 条）', 'supplementary_sft_template')]:
        comp = report[key]
        before, after = comp['before'], comp['after']
        lines.extend(['', f'## {title}', '', f"样本数：{before['samples']}。", '',
                      '| 指标 | 原始 Qwen3-8B | QLoRA 适配器 |', '| --- | ---: | ---: |'])
        for label, metric in [('分类准确率', 'accuracy_all_samples'), ('宏平均 F1', 'macro_f1_present_classes'),
                              ('正常访问判为攻击', 'normal_flagged_attack_rate'),
                              ('正常访问无法识别', 'normal_unclassified_rate'),
                              ('攻击判为正常', 'attack_predicted_normal_rate'),
                              ('四段格式完整率', 'four_sections_rate')]:
            lines.append(f'| {label} | {pct(before[metric])} | {pct(after[metric])} |')
        lines.extend(['', f"逐条比较：纠正 {comp['paired']['improved']} 条，退化 {comp['paired']['regressed']} 条。",
                      f"生成状态：原始 {before['status_counts']}；适配器 {after['status_counts']}。",
                      f"结束原因：原始 {before['finish_reason_counts']}；适配器 {after['finish_reason_counts']}。"])
        for source in sorted(before['by_source']):
            x, y = before['by_source'][source], after['by_source'][source]
            lines.extend(['', f'### {source}', '',
                          '| 类别 | 样本数 | 原始召回率 | 微调后召回率 |', '| --- | ---: | ---: | ---: |'])
            for label in sorted(x['per_class']):
                lines.append(f"| {label} | {x['per_class'][label]['support']} | "
                             f"{pct(x['per_class'][label]['recall'])} | {pct(y['per_class'][label]['recall'])} |")
    with path_md.open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines) + '\n')
    print('paired reports saved', path_json, path_md, flush=True)


if __name__ == '__main__':
    main()
