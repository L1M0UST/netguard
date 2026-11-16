#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
bash -n "$work/wait_qwen_vllm.sh"
"$work/env312/bin/python" - <<'PY'
import collections,json,tempfile
from pathlib import Path
import evaluate_qwen_vllm as e
from transformers import AutoTokenizer

rows=[json.loads(s) for s in e.DATA.read_text(encoding='utf-8').splitlines() if s]
assert len(rows)==300
assert len({r['_meta']['record_id'] for r in rows})==len(rows)
tokenizer=AutoTokenizer.from_pretrained(str(e.MODEL),local_files_only=True)
primary=e.prepare(rows,tokenizer,'official_nothink')
aux=e.prepare(e.stratified_first(rows),tokenizer,'sft_template')
assert len(aux)==75
assert max(r['input_tokens'] for r in primary)<=e.MAX_INPUT_TOKENS
assert max(r['input_tokens'] for r in aux)<=e.MAX_INPUT_TOKENS
for item in rows[:3]:
    sft=e.prompt_for(item,tokenizer,'sft_template')
    official=e.prompt_for(item,tokenizer,'official_nothink')
    assert official==sft+'<think>\n\n</think>\n\n'
print('dev rows',len(rows),'supplementary',len(aux),'max_input_tokens',
      max(r['input_tokens'] for r in primary))
print('dev strata',len({(r['_meta']['source'],r['_meta']['label']) for r in rows}))

class Output:
    text='【研判结论】\n攻击类型：正常访问\n【判定依据】\n证据\n【ATT&CK映射】\n无\n【处置建议】\n检查'
    token_ids=[1,2,3]
    finish_reason='stop'
class Result:
    outputs=[Output()]
class Engine:
    def generate(self,inputs,*args,**kwargs): return [Result() for _ in inputs]

e.version=lambda name:'self-check'
with tempfile.TemporaryDirectory() as d:
    e.REPORTS=Path(d)
    sample=primary[:3]+[dict(primary[3],input_tokens=2049)]
    e.evaluate(Engine(),None,sample,'check','official_nothink',None,'testsha')
    summary=json.loads((e.REPORTS/'check/summary.json').read_text(encoding='utf-8'))
    preds=[json.loads(x) for x in (e.REPORTS/'check/predictions.jsonl').read_text(encoding='utf-8').splitlines()]
    assert summary['samples']==4 and len(preds)==4
    assert summary['status_counts']=={'ok':3,'input_too_long':1}
    assert all(x['prediction']=='正常访问' and x['four_sections'] for x in preds[:3])
    assert preds[-1]['prediction']==''
print('CPU evaluator self-check passed (fake engine; not a real vLLM/GPU test)')
PY
