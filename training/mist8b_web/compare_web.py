"""Compare the same balanced development records before and after QLoRA."""
from __future__ import annotations

import json
from pathlib import Path

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')


def load(name: str):
    directory = WORK / 'reports' / name
    summary = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
    predictions = [json.loads(line) for line in (directory / 'predictions.jsonl').read_text(encoding='utf-8').splitlines()]
    return summary, predictions


def pct(value):
    return '--' if value is None else f'{value*100:.2f}%'


def main():
    before, base = load('baseline')
    after, tuned = load('adapter')
    assert before['data_sha256'] == after['data_sha256']
    assert [(p['record_id'],p['truth']) for p in base] == [(p['record_id'],p['truth']) for p in tuned]
    report = {'samples': len(base), 'data_sha256': before['data_sha256'],
              'before': before, 'after': after,
              'paired': {'improved': sum(a['prediction']!=a['truth'] and b['prediction']==b['truth'] for a,b in zip(base,tuned)),
                         'regressed': sum(a['prediction']==a['truth'] and b['prediction']!=b['truth'] for a,b in zip(base,tuned))},
              'interpretation': 'Balanced development sample, not a sealed test or full-system result; source labels have not been independently audited.'}
    out = WORK/'reports/comparison.json'
    out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    lines = ['# MiST-8B Web 第一轮：验证集对比', '',
        '以下为按来源和类别均衡抽取的 300 条验证样本，同一输入与生成设置；不是封存测试集或系统验收指标。', '',
        '| 指标 | 微调前 | 微调后 |', '| --- | ---: | ---: |']
    for label,key in [('分类准确率','accuracy_all_samples'),('宏平均 F1','macro_f1_present_classes'),
                      ('正常访问判为攻击','normal_flagged_attack_rate'),('正常访问无法识别','normal_unclassified_rate'),
                      ('攻击误判为正常','attack_predicted_normal_rate'),('四段格式完整率','four_sections_rate')]:
        lines.append(f'| {label} | {pct(before[key])} | {pct(after[key])} |')
    for source in sorted(before['by_source']):
        x,y=before['by_source'][source],after['by_source'][source]
        lines.extend(['',f'## {source}', '', '| 类别 | 样本数 | 召回率：微调前 | 召回率：微调后 |', '| --- | ---: | ---: | ---: |'])
        for label in sorted(x['per_class']):
            lines.append(f"| {label} | {x['per_class'][label]['support']} | {pct(x['per_class'][label]['recall'])} | {pct(y['per_class'][label]['recall'])} |")
    lines.extend(['', f"逐条对比：纠正 {report['paired']['improved']} 条，退化 {report['paired']['regressed']} 条。",
        '', '数据标签来自原始数据源，回答中的依据和处置建议由模板生成；封存测试仍需另行评估。'])
    (WORK/'reports/comparison.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('comparison saved',out)


if __name__ == '__main__':
    main()
