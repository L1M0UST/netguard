"""Retain MiST adapter-only checkpoints before rotation, while training is active."""
from __future__ import annotations

import time
from pathlib import Path

import preserve_qwen_checkpoints as common

WORK=Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
common.RUN=WORK/'runs/round1'
common.OUT=WORK/'runs/mist_preserved_checkpoints'
common.REPORT=WORK/'reports/mist_preserved_checkpoints.json'
common.STATE=WORK/'reports/mist_checkpoint_monitor_state.txt'


def main()->None:
    common.OUT.mkdir(exist_ok=False)
    common.STATE.write_text('watching\n',encoding='utf-8')
    for _ in range(48*120):
        for p in sorted(common.RUN.glob('checkpoint-*')):
            if p.is_dir():common.capture(p)
        common.write_report()
        state=(WORK/'reports/mist_after_qwen_state.txt').read_text().strip()
        if state!='training_mist':
            common.STATE.write_text('training_ended_preserved_checkpoints_available\n',encoding='utf-8')
            return
        time.sleep(30)
    common.STATE.write_text('timeout\n',encoding='utf-8')


if __name__=='__main__':
    try:main()
    except Exception as exc:
        common.STATE.write_text('failed: '+type(exc).__name__+'\n',encoding='utf-8')
        raise
