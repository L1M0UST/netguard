"""Create manifests for stable files in incoming; never start billable processing."""
import argparse
import json
import os
import time
from pathlib import Path

PREFIXES = {'.xlsx':'excel', '.xls':'excel', '.csv':'csv', '.json':'json',
            '.jsonl':'jsonl', '.ndjson':'jsonl', '.pcap':'pcap', '.cap':'pcap', '.pcapng':'pcapng'}


def scan(workspace, previous):
    workspace = Path(workspace).resolve()
    incoming, manifests = workspace/'incoming', workspace/'manifests'
    incoming.mkdir(parents=True, exist_ok=True)
    manifests.mkdir(parents=True, exist_ok=True)
    known = set()
    for path in manifests.glob('*.json'):
        # Do not silently ignore a malformed existing task and create duplicates.
        task = json.loads(path.read_text(encoding='utf-8-sig'))
        for name in task.get('input_files', []):
            known.add((workspace/name).resolve())
    current, created = {}, []
    for path in sorted(incoming.iterdir()):
        prefix = PREFIXES.get(path.suffix.lower())
        if not path.is_file() or not prefix or path.name.startswith(('~$', '.')): continue
        resolved = path.resolve()
        if resolved.parent != incoming.resolve() or resolved in known: continue
        try:
            stat = path.stat()
            signature = (stat.st_size, stat.st_mtime_ns)
            current[path.name] = signature
            if stat.st_size == 0 or previous.get(path.name) != signature: continue
            with path.open('rb') as stream: stream.read(1)
            # New tasks use unique names; existing files and manifests stay intact.
            number = 1
            while True:
                task_id = f'{prefix}-{number:03d}'
                target = manifests/(task_id+'.json')
                try:
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                    break
                except FileExistsError: number += 1
            task = {'schema_version':'1.0', 'task_id':task_id, 'batch_id':'batch-'+task_id,
                    'input_files':[path.relative_to(workspace).as_posix()],
                    'options':{'session_window_seconds':300}}
            with os.fdopen(fd,'w',encoding='utf-8') as stream:
                json.dump(task,stream,ensure_ascii=False,indent=2)
            created.append(target)
            known.add(resolved)
        except (PermissionError, FileNotFoundError):
            continue  # Still being copied or replaced; retry next scan.
    return current, created


def main():
    parser = argparse.ArgumentParser(description='Generate M1 manifests for incoming files')
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--watch',action='store_true',help='Keep scanning until Ctrl+C')
    parser.add_argument('--interval',type=float,default=3)
    args = parser.parse_args()
    if not 1 <= args.interval <= 60: parser.error('interval must be between 1 and 60 seconds')
    root = args.workspace.resolve()
    lock = root/'manifests/.intake.lock'
    lock.parent.mkdir(parents=True,exist_ok=True)
    try:
        fd = os.open(lock,os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        parser.error('An intake process is running, or a stale manifests/.intake.lock exists. Stop the old process before removing a stale lock.')
    os.close(fd)
    print('Watching incoming; manifests only, M1 is not started. Ctrl+C to stop.',flush=True)
    previous = {}
    try:
        for initial in (True, False):
            previous, created = scan(root,previous)
            for path in created: print('Created: '+str(path),flush=True)
            if initial: time.sleep(args.interval)
        while args.watch:
            time.sleep(args.interval)
            previous, created = scan(root,previous)
            for path in created: print('Created: '+str(path),flush=True)
    except KeyboardInterrupt:
        print('Stopped.')
    finally:
        lock.unlink(missing_ok=True)


if __name__ == '__main__': main()
