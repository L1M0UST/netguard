"""Expire only M3-owned uploaded copies; never delete users' original files."""
import time
import re
from pathlib import Path


def expire_uploads(files, tasks, data_dir, workspace, ttl_hours=72, now=None):
    now = time.time() if now is None else now
    if ttl_hours <= 0:
        return []
    removed = []
    for file_id, record in files.items():
        if not re.fullmatch(r'[a-f0-9]{32}', file_id) or not record.get('uploaded_at_epoch'):
            continue
        if now-record['uploaded_at_epoch'] < ttl_hours*3600 or record.get('raw_expired'):
            continue
        owners=[t for t in tasks.values() if file_id in t.get('file_ids', [])]
        if any(t['status'] not in {'completed','failed'} for t in owners):
            continue
        paths=[Path(data_dir)/file_id]
        for task in owners:
            # PROCESSING is owned by M1; M3 never removes files there.
            paths.extend(workspace.task_path('m3', state, task['task_id'])/file_id for state in ('READY','DONE'))
        for path in paths:
            if path.is_file() and not path.is_symlink():
                path.unlink()
        record['raw_expired']=True
        removed.append(file_id)
    return removed
