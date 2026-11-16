"""Exercise report comparison and adapter packaging with temporary fixtures."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from zipfile import ZipFile

import compare_web
import evaluate_web
import export_artifact


def main() -> None:
    with tempfile.TemporaryDirectory(prefix='mist_web_report_check_') as tmp:
        root=Path(tmp)
        before=[{'record_id':'1','source':'D0','truth':'正常访问','prediction':'SQL注入攻击','status':'ok','four_sections':False},
                {'record_id':'2','source':'D0','truth':'远程命令执行攻击','prediction':'远程命令执行攻击','status':'ok','four_sections':True}]
        after=[dict(before[0],prediction='正常访问',four_sections=True),dict(before[1],prediction='')]
        for name,rows in [('baseline',before),('adapter',after)]:
            directory=root/'reports'/name
            directory.mkdir(parents=True)
            summary=evaluate_web.metrics(rows)
            summary.update({'data_sha256':'test','by_source':{'D0':evaluate_web.metrics(rows)}})
            (directory/'summary.json').write_text(json.dumps(summary,ensure_ascii=False),encoding='utf-8')
            (directory/'predictions.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf-8')
        compare_web.WORK=root
        compare_web.main()
        report=json.loads((root/'reports/comparison.json').read_text(encoding='utf-8'))
        assert report['paired']=={'improved':1,'regressed':1}
        assert '远程命令执行攻击' in (root/'reports/comparison.md').read_text(encoding='utf-8')
        paths=['runs/round1/adapter_config.json','runs/round1/adapter_model.safetensors',
            'configs/round1.yaml','configs/smoke.yaml','configs/profile.yaml',
            'models/MiST-8B-transformers4/tokenizer_config.json','models/MiST-8B-transformers4/COMPATIBILITY.json',
            'models/MiST-8B/tokenizer.json','models/MiST-8B/chat_template.jinja','models/MiST-8B/LICENSE',
            'models/MiST-8B/NOTICE','reports/model-verified.txt','reports/token_audit_v2.json',
            'reports/data_report_v4.json','reports/environment312-verified-freeze.txt',
            'logs/smoke.log','logs/profile.log','logs/round1.log']
        for name in paths:
            path=root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('fixture',encoding='utf-8')
        (root/'reports/pipeline-state.txt').write_text('complete\n')
        export_artifact.WORK=root
        export_artifact.OUT=root/'exports/mist8b-web-round1.zip'
        export_artifact.main()
        with ZipFile(export_artifact.OUT) as archive:
            assert archive.testzip() is None
            assert {'tokenizer/tokenizer.json','tokenizer/tokenizer_config.json','runs/round1/adapter_model.safetensors','manifest.json'}.issubset(archive.namelist())
        print('report comparison and export fixtures passed')


if __name__=='__main__':
    main()
