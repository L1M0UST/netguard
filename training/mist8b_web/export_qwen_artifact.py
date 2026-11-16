"""Package the Qwen3-8B stage-1 adapter, configs and reports (no base weights)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
OUT = WORK / 'exports/qwen3-web-stage1.zip'


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    assert (WORK / 'reports/qwen_stage1_state.txt').read_text().strip() == 'complete'
    assert (WORK / 'reports/qwen_comparison.json').exists()
    names = [
        'runs/qwen3_round1/adapter_config.json',
        'runs/qwen3_round1/adapter_model.safetensors',
        'runs/qwen3_round1/trainer_state.json',
        'configs/qwen3_smoke.yaml',
        'configs/qwen3_round1.yaml',
        'models/Qwen3-8B-ModelScope/config.json',
        'models/Qwen3-8B-ModelScope/generation_config.json',
        'models/Qwen3-8B-ModelScope/tokenizer_config.json',
        'models/Qwen3-8B-ModelScope/tokenizer.json',
        'reports/qwen3_download.json',
        'reports/qwen_token_audit.json',
        'reports/data_report_v4.json',
        'reports/environment312-verified-freeze.txt',
        'reports/qwen_baseline/summary.json',
        'reports/qwen_adapter/summary.json',
        'reports/qwen_baseline/predictions.jsonl',
        'reports/qwen_adapter/predictions.jsonl',
        'reports/qwen_comparison.json',
        'reports/qwen_comparison.md',
        'logs/qwen_token_audit.log',
        'logs/qwen3_smoke.log',
        'logs/qwen_baseline_eval.log',
        'logs/qwen3_round1.log',
        'logs/qwen_adapter_eval.log',
    ]
    for name in names:
        if not (WORK / name).is_file():
            raise FileNotFoundError(name)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    manifest = {}
    with ZipFile(OUT, 'x', compression=ZIP_DEFLATED, compresslevel=4, allowZip64=True) as archive:
        for name in names:
            path = WORK / name
            manifest[name] = {'bytes': path.stat().st_size, 'sha256': sha256(path)}
            archive.write(path, name)
        archive.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
        archive.writestr('README.txt', '''Qwen3-8B Web stage 1: QLoRA adapter, configs and validation reports.
Base model: Qwen/Qwen3-8B from ModelScope, revision 26028140be3ee69b82b1d1450179ab71bb1121b9
(16,397,461,896 bytes, all files SHA-256 verified). Base weights are NOT included.
Load runs/qwen3_round1/ with PEFT on top of the base. adapter_config.json may contain the
server's absolute base path; supply your local base model explicitly.
Baseline and adapter reports share the same balanced 300-record dev sample, which is not the
sealed test set and not a full-system acceptance result. Labels come from source datasets.
''')
    with ZipFile(OUT) as archive:
        assert archive.testzip() is None
    digest = sha256(OUT)
    (WORK / 'exports/qwen3-web-stage1.sha256').write_text(digest + '\n')
    print('export_ready bytes', OUT.stat().st_size, 'sha256', digest, flush=True)


if __name__ == '__main__':
    main()
