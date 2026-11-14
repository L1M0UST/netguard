"""Confine remote file selection to the top level of shared incoming."""
import hashlib
from pathlib import Path
from m1.intake import PREFIXES


def resolve_file(workspace, name):
    if not isinstance(name,str) or not name or name in ('.','..') or any(c in name for c in '/\\:'):
        raise ValueError('Invalid file name')
    root = (Path(workspace).resolve()/'incoming').resolve()
    path = root/name
    if path.is_symlink() or path.resolve().parent != root or not path.is_file():
        raise ValueError('File not found in incoming')
    if path.suffix.lower() not in PREFIXES or name.startswith(('~$','.')):
        raise ValueError('Unsupported file')
    if path.stat().st_size == 0: raise ValueError('Empty file')
    return path


def descriptor(path):
    stat = path.stat()
    version = f'{path.name}\0{stat.st_size}\0{stat.st_mtime_ns}'
    return {'file_id':hashlib.sha256(version.encode()).hexdigest(), 'name':path.name,
            'size_bytes':stat.st_size, 'modified_ns':str(stat.st_mtime_ns), 'format':path.suffix.lower()[1:]}


def list_files(workspace):
    root = Path(workspace).resolve()/'incoming'
    root.mkdir(parents=True,exist_ok=True)
    result = []
    for entry in sorted(root.iterdir()):
        try: result.append(descriptor(resolve_file(workspace,entry.name)))
        except (ValueError,OSError): continue
    return result
