"""Offline audit of the user's workbook, without changing published batches."""
import json
import shutil
from pathlib import Path
from uuid import uuid4
from m1.run import process


def main():
    workspace = Path('shared-workspace').resolve()
    root = Path('tests/.test-workspaces') / str(uuid4())
    root.mkdir(parents=True)
    try:
        (root / 'm1').mkdir()
        (root / 'm1/config.json').write_text(json.dumps({'output': {'format': 'parquet', 'batch_size': 500}, 'enable_l3_semantic_judge': False}), encoding='utf-8')
        manifest = root / 'manifest.json'
        manifest.write_text(json.dumps({'task_id': 'offline-duty-audit', 'input_files': [str(workspace / 'incoming/web_alerts.xlsx')]}), encoding='utf-8')
        ready = process(root.resolve(), manifest.resolve())
        import pyarrow.parquet as pq
        status = json.loads((ready / 'status.json').read_text(encoding='utf-8'))
        details = pq.read_table(ready / 'event_details.parquet', columns=['event_id']).column(0).to_pylist()
        sessions = pq.read_table(ready / 'all_sessions.parquet').to_pylist()
        refs = {ref for row in sessions for ref in row['related_event_ids']}
        assert refs == set(details)
        assert sum(row['event_count'] for row in sessions) == len(details)
        assert all(0 <= row['risk_score'] <= 100 for row in sessions)
        print(json.dumps({'metrics': status['metrics'], 'references_valid': True, 'llm_calls': status['llm_calls']}))
    finally:
        shutil.rmtree(root)


if __name__ == '__main__':
    main()
