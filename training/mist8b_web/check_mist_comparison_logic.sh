#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
"$work/env312/bin/python" - <<'PY'
import json,tempfile
from pathlib import Path
import compare_mist_vllm as mist
import compare_qwen_mist_vllm as cross
import compare_qwen_vllm as common
from evaluate_web import metrics
with tempfile.TemporaryDirectory() as d:
 root=Path(d);reports=root/'reports';reports.mkdir()
 common.REPORTS=reports;mist.REPORTS=reports;cross.WORK=root
 predictions=[{'record_id':'1','source':'synthetic','truth':'正常访问','prediction':'正常访问','status':'ok','four_sections':True},
              {'record_id':'2','source':'synthetic','truth':'远程命令执行攻击','prediction':'正常访问','status':'ok','four_sections':True}]
 summary=metrics(predictions);summary['by_source']={'synthetic':metrics(predictions)}
 summary.update({'data_sha256':'x','template':'official_nothink','max_input_tokens':2048,'max_new_tokens':256,
                 'temperature':0.0,'engine_version':'0.8.5','base_precision':'bfloat16','finish_reason_counts':{'stop':2}})
 for model in ('qwen','mist'):
  for template in ('official','sftprompt'):
   for variant in ('baseline','adapter'):
    directory=reports/f'{model}_vllm_{template}_{variant}';directory.mkdir()
    (directory/'summary.json').write_text(json.dumps(summary,ensure_ascii=False),encoding='utf-8')
    (directory/'predictions.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in predictions),encoding='utf-8')
 mist.main();cross.main()
 assert (reports/'mist_vllm_comparison.md').exists() and (reports/'qwen_mist_vllm_comparison.md').exists()
 print('MiST and cross-model comparison self-check passed with synthetic data')
PY
