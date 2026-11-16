"""Back up MiST adapter alone or with the vLLM evaluation reports."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

WORK=Path('/root/sj-tmp/cqsec_mist8b_web_20261115')


def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for part in iter(lambda:f.read(4*1024*1024),b''): h.update(part)
    return h.hexdigest()


def main() -> None:
    ap=argparse.ArgumentParser();ap.add_argument('--evaluated',action='store_true');args=ap.parse_args()
    mode='vllm' if args.evaluated else 'adapter'
    out=WORK/f'exports/mist8b-web-stage1-{mode}.zip'
    names=['runs/round1/adapter_config.json','runs/round1/adapter_model.safetensors','runs/round1/trainer_state.json',
           'configs/smoke.yaml','configs/round1.yaml','reports/model-verified.txt','reports/token_audit_v2.json',
           'reports/data_report_v4.json','reports/environment312-verified-freeze.txt',
           'models/MiST-8B-transformers4/COMPATIBILITY.json','models/MiST-8B-transformers4/config.json',
           'models/MiST-8B-transformers4/tokenizer_config.json','models/MiST-8B-transformers4/tokenizer.json',
           'logs/mist_smoke_after_qwen.log','logs/mist_round1_after_qwen.log']
    if args.evaluated:
        names+=['reports/vllm_environment_freeze.txt','reports/mist_vllm_comparison.json','reports/mist_vllm_comparison.md',
                'reports/qwen_mist_vllm_comparison.json','reports/qwen_mist_vllm_comparison.md',
                'logs/mist_vllm_evaluation.log','evaluate_mist_vllm.py','evaluate_qwen_vllm.py',
                'compare_mist_vllm.py','compare_qwen_mist_vllm.py','compare_qwen_vllm.py','evaluate_web.py']
        for template in ('official','sftprompt'):
            for variant in ('baseline','adapter'):
                for filename in ('predictions.jsonl','summary.json'):
                    names.append(f'reports/mist_vllm_{template}_{variant}/{filename}')
    for name in names:
        if not (WORK/name).is_file():raise FileNotFoundError(WORK/name)
    out.parent.mkdir(parents=True,exist_ok=True);manifest={}
    with ZipFile(out,'x',compression=ZIP_DEFLATED,compresslevel=4,allowZip64=True) as z:
        for name in names:
            p=WORK/name;manifest[name]={'bytes':p.stat().st_size,'sha256':sha256(p)};z.write(p,name)
        z.writestr('manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
        z.writestr('README.txt', '''MiST-8B Web stage 1 QLoRA adapter.
Base: MiST-8B, revision 9ba377df00b9e830849fce8ebbe568a9a84774f2. Base weights not included.
The tokenizer compatibility files adjust Transformers-4 token metadata; original weights are unchanged.
Do not apply this adapter to Qwen. Results, if included, are development-only and not full-system results.
''')
    with ZipFile(out) as z:assert z.testzip() is None
    digest=sha256(out)
    (WORK/f'exports/mist8b-web-stage1-{mode}.sha256').write_text(digest+'\n',encoding='ascii')
    print('MiST archive ready',out.stat().st_size,digest,flush=True)


if __name__=='__main__':main()
