"""Produce MiST's paired dev report with the same metric code used for Qwen."""
from __future__ import annotations

import json
from pathlib import Path

import compare_qwen_vllm as common

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
REPORTS = WORK / 'reports'


def pct(value):
    return '--' if value is None else f'{100*value:.2f}%'


def main() -> None:
    original_load = common.load
    common.load = lambda name: original_load(name.replace('qwen_vllm_', 'mist_vllm_', 1))
    report = {
        'model': 'MiST-8B revision 9ba377df00b9e830849fce8ebbe568a9a84774f2',
        'primary_official_nothink': common.compare('official'),
        'supplementary_sft_template': common.compare('sftprompt'),
        'interpretation': ('Development set only, with source-derived labels; not a sealed-test or '
                           'end-to-end result. Both sides of each comparison use BF16 vLLM.'),
    }
    path_json, path_md = REPORTS/'mist_vllm_comparison.json', REPORTS/'mist_vllm_comparison.md'
    if path_json.exists() or path_md.exists():
        raise FileExistsError('MiST comparison report exists')
    with path_json.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    lines = ['# MiST-8B 第一轮 Web 研判：vLLM 验证集对比', '',
             '基座和适配器使用相同 BF16 vLLM、生成参数和提示词；数据源标签未逐条人工复核。',
             '此处为开发验证，并非封存测试或系统验收指标。']
    for title,key in [('官方关闭思考模板', 'primary_official_nothink'),
                      ('训练时模板的分层抽样', 'supplementary_sft_template')]:
        comp=report[key];before=comp['before'];after=comp['after']
        lines.extend(['',f'## {title}','',f"样本数：{before['samples']}。",'',
                      '| 指标 | 原始 MiST-8B | MiST QLoRA |','| --- | ---: | ---: |'])
        for label,metric in [('分类准确率','accuracy_all_samples'),('宏平均 F1','macro_f1_present_classes'),
                             ('正常访问判为攻击','normal_flagged_attack_rate'),('正常访问无法识别','normal_unclassified_rate'),
                             ('攻击判为正常','attack_predicted_normal_rate'),('四段格式完整率','four_sections_rate')]:
            lines.append(f'| {label} | {pct(before[metric])} | {pct(after[metric])} |')
        lines.extend(['',f"逐条比较：纠正 {comp['paired']['improved']} 条，退化 {comp['paired']['regressed']} 条。",
                      f"生成状态：原始 {before['status_counts']}；适配器 {after['status_counts']}。",
                      f"结束原因：原始 {before['finish_reason_counts']}；适配器 {after['finish_reason_counts']}。"])
        for source in sorted(before['by_source']):
            x,y=before['by_source'][source],after['by_source'][source]
            lines.extend(['',f'### {source}','','| 类别 | 样本数 | 原始召回率 | 微调后召回率 |',
                          '| --- | ---: | ---: | ---: |'])
            for label in sorted(x['per_class']):
                lines.append(f"| {label} | {x['per_class'][label]['support']} | "
                             f"{pct(x['per_class'][label]['recall'])} | {pct(y['per_class'][label]['recall'])} |")
    with path_md.open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines)+'\n')
    print('MiST paired reports saved',path_json,path_md,flush=True)


if __name__ == '__main__':
    main()
