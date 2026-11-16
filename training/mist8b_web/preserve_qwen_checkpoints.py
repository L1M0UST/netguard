"""Retain each completed LoRA checkpoint before Trainer rotates older saves.

Only the adapter, config and trainer state are retained; optimizer state is
not copied, so these are evaluation candidates, not resumable checkpoints.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path

from safetensors import safe_open

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
RUN = WORK / 'runs/qwen3_round1'
OUT = WORK / 'runs/qwen3_preserved_checkpoints'
REPORT = WORK / 'reports/qwen_preserved_checkpoints.json'
STATE = WORK / 'reports/qwen_checkpoint_monitor_state.txt'


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4*1024*1024), b''):
            sha.update(chunk)
    return sha.hexdigest()


def capture(source: Path) -> bool:
    try:
        step = int(source.name.removeprefix('checkpoint-'))
    except ValueError:
        return False
    target = OUT / source.name
    if target.exists():
        return False
    names = ('adapter_config.json', 'adapter_model.safetensors', 'trainer_state.json')
    if not all((source / name).is_file() for name in names):
        return False
    try:
        trainer = json.loads((source / 'trainer_state.json').read_text(encoding='utf-8'))
        if trainer.get('global_step') != step:
            return False
        config = json.loads((source / 'adapter_config.json').read_text(encoding='utf-8'))
        if config.get('r') != 16:
            raise ValueError('unexpected LoRA rank')
        sizes = {name: (source / name).stat().st_size for name in names}
        if any(size <= 0 for size in sizes.values()):
            return False
        time.sleep(2)
        if any((source / name).stat().st_size != sizes[name] for name in names):
            return False
        temp = OUT / (source.name + '.copying')
        temp.mkdir(exist_ok=False)
        for name in names:
            shutil.copy2(source / name, temp / name)
        with safe_open(str(temp / 'adapter_model.safetensors'), framework='pt', device='cpu') as tensors:
            if len(tensors.keys()) == 0:
                raise ValueError('empty adapter')
        evaluation = [entry for entry in trainer.get('log_history', [])
                      if entry.get('step') == step and 'eval_loss' in entry]
        metadata = {'step': step, 'eval_loss': evaluation[-1]['eval_loss'] if evaluation else None,
                    'files': {name: {'bytes': (temp/name).stat().st_size, 'sha256': digest(temp/name)}
                              for name in names},
                    'note': 'adapter-only candidate; validation loss is not a classification metric'}
        (temp / 'candidate.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        os.rename(temp, target)
        print('checkpoint preserved', step, 'eval_loss', metadata['eval_loss'], flush=True)
        return True
    except (FileNotFoundError, json.JSONDecodeError):
        # Trainer may still be writing this checkpoint; retry on the next scan.
        return False


def write_report() -> None:
    candidates = [json.loads(p.read_text(encoding='utf-8')) for p in sorted(OUT.glob('checkpoint-*/candidate.json'))]
    candidates.sort(key=lambda x: x['step'])
    evaluated = [c for c in candidates if isinstance(c['eval_loss'], (float, int))]
    report = {'candidates': candidates,
              'lowest_validation_loss_step': min(evaluated,key=lambda c:c['eval_loss'])['step'] if evaluated else None,
              'note': 'Development loss is a selection aid, not proof of classification quality; evaluate on held-out data.'}
    tmp = REPORT.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    os.replace(tmp, REPORT)


def main() -> None:
    OUT.mkdir(exist_ok=False)
    STATE.write_text('watching\n', encoding='utf-8')
    for _ in range(48*120):
        for path in sorted(RUN.glob('checkpoint-*')):
            if path.is_dir():
                capture(path)
        write_report()
        train = (WORK / 'reports/qwen_round1_now_state.txt').read_text().strip()
        if train == 'training_complete_waiting_for_vllm_evaluation':
            STATE.write_text('complete\n', encoding='utf-8')
            return
        if train.startswith(('failed', 'gpu_busy')):
            STATE.write_text('training_failed_preserved_available_checkpoints\n', encoding='utf-8')
            return
        time.sleep(30)
    STATE.write_text('timeout\n', encoding='utf-8')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        STATE.write_text('failed: '+type(exc).__name__+'\n', encoding='utf-8')
        raise
