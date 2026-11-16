"""Export the real Qwen adapter and paired vLLM dev evidence, not base weights."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
OUT = WORK / 'exports/qwen3-web-stage1-vllm.zip'


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    names = [
        'runs/qwen3_round1/adapter_config.json', 'runs/qwen3_round1/adapter_model.safetensors',
        'runs/qwen3_round1/trainer_state.json', 'configs/qwen3_round1.yaml',
        'models/Qwen3-8B-ModelScope/config.json', 'models/Qwen3-8B-ModelScope/generation_config.json',
        'models/Qwen3-8B-ModelScope/tokenizer_config.json', 'models/Qwen3-8B-ModelScope/tokenizer.json',
        'reports/qwen3_download.json', 'reports/qwen_token_audit.json', 'reports/data_report_v4.json',
        'reports/environment312-verified-freeze.txt', 'reports/vllm_environment_freeze.txt',
        'reports/qwen_vllm_comparison.json', 'reports/qwen_vllm_comparison.md',
        'logs/qwen3_round1.log', 'logs/qwen_vllm_evaluation.log',
        'evaluate_qwen_vllm.py', 'compare_qwen_vllm.py', 'evaluate_web.py',
    ]
    for template in ('official', 'sftprompt'):
        for variant in ('baseline', 'adapter'):
            for filename in ('predictions.jsonl', 'summary.json'):
                names.append(f'reports/qwen_vllm_{template}_{variant}/{filename}')
    for name in names:
        if not (WORK / name).is_file():
            raise FileNotFoundError(WORK / name)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    manifest = {}
    with ZipFile(OUT, 'x', compression=ZIP_DEFLATED, compresslevel=4, allowZip64=True) as archive:
        for name in names:
            path = WORK / name
            manifest[name] = {'bytes': path.stat().st_size, 'sha256': sha256(path)}
            archive.write(path, name)
        archive.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
        archive.writestr('README.txt', '''Qwen3-8B Web stage 1: QLoRA adapter and vLLM development comparisons.
Base: Qwen/Qwen3-8B, ModelScope revision 26028140be3ee69b82b1d1450179ab71bb1121b9.
The base weights are NOT included. The adapter is specific to that base, not MiST-8B.
Both sides use the same vLLM BF16 inference and decoding settings within each comparison.
The primary comparison uses official no-thinking prompts on the 300-row balanced dev set;
the supplementary comparison uses the SFT prompt on a smaller stratified dev subset.
Data-source labels have not been independently audited; no sealed test or full-system result is claimed.
''')
    with ZipFile(OUT) as archive:
        assert archive.testzip() is None
    digest = sha256(OUT)
    (WORK / 'exports/qwen3-web-stage1-vllm.sha256').write_text(digest + '\n', encoding='ascii')
    print('export_ready bytes', OUT.stat().st_size, 'sha256', digest, flush=True)


if __name__ == '__main__':
    main()
