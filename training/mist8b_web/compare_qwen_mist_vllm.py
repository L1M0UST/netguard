"""Compare Qwen and MiST on exactly matched development records and settings."""
from __future__ import annotations

import json
from pathlib import Path

from compare_qwen_vllm import load

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')


def pct(value):
    return '--' if value is None else f'{100*value:.2f}%'


def main() -> None:
    variants = [('qwen_base','qwen_vllm_official_baseline'),('qwen_lora','qwen_vllm_official_adapter'),
                ('mist_base','mist_vllm_official_baseline'),('mist_lora','mist_vllm_official_adapter')]
    results={};ids=None;settings=None
    for label,name in variants:
        summary,preds=load(name)
        current=[(p['record_id'],p['truth']) for p in preds]
        check=tuple(summary[k] for k in ('data_sha256','template','max_input_tokens','max_new_tokens',
                                          'temperature','engine_version','base_precision'))
        if ids is None: ids,settings=current,check
        assert current==ids and check==settings,'cross-model records or inference settings differ'
        results[label]=summary
    report={'variants':results,'samples':len(ids),
            'interpretation':'Matched balanced development records with source labels; not a sealed-test or end-to-end system result.'}
    path=WORK/'reports/qwen_mist_vllm_comparison.json'
    path_md=WORK/'reports/qwen_mist_vllm_comparison.md'
    if path.exists() or path_md.exists(): raise FileExistsError('cross-model report exists')
    with path.open('x',encoding='utf-8') as f:
        json.dump(report,f,ensure_ascii=False,indent=2);f.write('\n')
    lines=['# Qwen3-8B 与 MiST-8B：匹配验证集对比','',
           f"{len(ids)} 条来源和类别均衡的开发样本；相同提示词模式和 vLLM BF16 生成配置。",
           '原始数据源标签未逐条人工复核；本表不代表封存测试或完整系统表现。','',
           '| 指标 | Qwen 原始 | Qwen QLoRA | MiST 原始 | MiST QLoRA |',
           '| --- | ---: | ---: | ---: | ---: |']
    for label,key in [('分类准确率','accuracy_all_samples'),('宏平均 F1','macro_f1_present_classes'),
                      ('正常访问判为攻击','normal_flagged_attack_rate'),('正常访问无法识别','normal_unclassified_rate'),
                      ('攻击判为正常','attack_predicted_normal_rate'),('四段格式完整率','four_sections_rate')]:
        lines.append('| '+label+' | '+' | '.join(pct(results[n][key]) for n,_ in variants)+' |')
    sources=sorted(results['qwen_base']['by_source'])
    for source in sources:
        label='远程命令执行攻击'
        if label not in results['qwen_base']['by_source'][source]['per_class']: continue
        r=[results[n]['by_source'][source]['per_class'][label] for n,_ in variants]
        lines.extend(['',f"{source}：远程命令执行类别样本数 {r[0]['support']}；各版本召回率依次为 "
                      +'、'.join(pct(x['recall']) for x in r)+'。'])
    with path_md.open('x',encoding='utf-8') as f:f.write('\n'.join(lines)+'\n')
    print('cross-model comparison saved',path,flush=True)


if __name__ == '__main__':
    main()
