"""Create a checked portable adapter and evaluation archive after training."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
OUT = WORK / 'exports/mist8b-web-round1.zip'


def main() -> None:
    assert (WORK/'reports/pipeline-state.txt').read_text().strip() == 'complete'
    assert (WORK/'reports/comparison.json').exists()
    names = [
        'runs/round1/adapter_config.json', 'runs/round1/adapter_model.safetensors',
        'configs/round1.yaml', 'configs/smoke.yaml', 'configs/profile.yaml',
        'models/MiST-8B-transformers4/tokenizer_config.json',
        'models/MiST-8B-transformers4/COMPATIBILITY.json',
        'models/MiST-8B/tokenizer.json', 'models/MiST-8B/chat_template.jinja',
        'models/MiST-8B/LICENSE', 'models/MiST-8B/NOTICE',
        'reports/model-verified.txt', 'reports/token_audit_v2.json',
        'reports/data_report_v4.json', 'reports/environment312-verified-freeze.txt',
        'reports/baseline/summary.json', 'reports/adapter/summary.json',
        'reports/baseline/predictions.jsonl', 'reports/adapter/predictions.jsonl',
        'reports/comparison.json', 'reports/comparison.md',
        'logs/smoke.log', 'logs/profile.log', 'logs/round1.log',
    ]
    for name in names:
        if not (WORK/name).is_file():
            raise FileNotFoundError(name)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    manifest = {}
    remap = {
        'models/MiST-8B-transformers4/tokenizer_config.json': 'tokenizer/tokenizer_config.json',
        'models/MiST-8B/tokenizer.json': 'tokenizer/tokenizer.json',
        'models/MiST-8B/chat_template.jinja': 'tokenizer/chat_template.jinja',
    }
    with ZipFile(OUT,'x',compression=ZIP_DEFLATED,compresslevel=4,allowZip64=True) as archive:
        for name in names:
            path = WORK/name
            h = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(4*1024*1024),b''):
                    h.update(chunk)
            archive_name = remap.get(name,name)
            manifest[archive_name] = {'source':name,'bytes':path.stat().st_size,'sha256':h.hexdigest()}
            archive.write(path,archive_name)
        archive.writestr('manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
        archive.writestr('README.txt', '''MiST-8B Web round 1: adapter, tokenizer compatibility files, and validation reports.
This archive does NOT contain base-model weights. The required base is dreamgroup/MiST-8B
at revision 9ba377df00b9e830849fce8ebbe568a9a84774f2 (SHA-256 recorded in reports).
For the recorded transformers 4.53.3 environment, use the files in tokenizer/ alongside
the verified base weights and load runs/round1/ with PEFT. The adapter configuration may
contain the server's original absolute base path; explicitly supply your local base model.
Baseline and adapter reports use the same balanced dev sample, not the sealed test set.
''')
    with ZipFile(OUT) as archive:
        assert archive.testzip() is None
    digest = hashlib.sha256()
    with OUT.open('rb') as stream:
        for chunk in iter(lambda:stream.read(4*1024*1024),b''):
            digest.update(chunk)
    (WORK/'exports/mist8b-web-round1.sha256').write_text(digest.hexdigest()+'\n')
    print('export_ready bytes',OUT.stat().st_size,'sha256',digest.hexdigest(),flush=True)


if __name__ == '__main__':
    main()
