"""Back up the completed adapter independently of the evaluation pipeline."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
OUT = WORK / 'exports/qwen3-web-stage1-adapter.zip'


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(4*1024*1024), b''):
            sha.update(data)
    return sha.hexdigest()


def main() -> None:
    assert (WORK / 'reports/qwen_round1_now_state.txt').read_text().strip() == 'training_complete_waiting_for_vllm_evaluation'
    names = [
        'runs/qwen3_round1/adapter_config.json', 'runs/qwen3_round1/adapter_model.safetensors',
        'runs/qwen3_round1/trainer_state.json', 'configs/qwen3_round1.yaml',
        'reports/qwen3_download.json', 'reports/qwen_token_audit.json', 'reports/data_report_v4.json',
        'reports/environment312-verified-freeze.txt', 'logs/qwen3_round1.log',
        'models/Qwen3-8B-ModelScope/config.json', 'models/Qwen3-8B-ModelScope/generation_config.json',
        'models/Qwen3-8B-ModelScope/tokenizer_config.json', 'models/Qwen3-8B-ModelScope/tokenizer.json',
    ]
    for name in names:
        if not (WORK / name).is_file():
            raise FileNotFoundError(WORK / name)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    files = {}
    with ZipFile(OUT, 'x', compression=ZIP_DEFLATED, compresslevel=4, allowZip64=True) as archive:
        for name in names:
            path = WORK / name
            files[name] = {'bytes': path.stat().st_size, 'sha256': digest(path)}
            archive.write(path, name)
        archive.writestr('manifest.json', json.dumps(files, ensure_ascii=False, indent=2) + '\n')
        archive.writestr('README.txt', '''Qwen3-8B Web stage 1 QLoRA adapter backup.
Base model: Qwen/Qwen3-8B ModelScope revision 26028140be3ee69b82b1d1450179ab71bb1121b9.
Base weights are NOT included. Adapter is for Qwen3-8B and cannot be applied to MiST-8B.
This archive records training completion; it does not claim evaluation results.
''')
    with ZipFile(OUT) as archive:
        assert archive.testzip() is None
    checksum = digest(OUT)
    (WORK / 'exports/qwen3-web-stage1-adapter.sha256').write_text(checksum+'\n', encoding='ascii')
    print('adapter backup ready:', OUT.stat().st_size, checksum, flush=True)


if __name__ == '__main__':
    main()
