"""Versioned M1 -> M2 batch contract and integrity verification."""
import hashlib
import json
from pathlib import Path

CONTRACT_VERSION = '2.0'


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_info(path):
    path = Path(path)
    if path.suffix == '.parquet':
        import pyarrow.parquet as pq
        rows = pq.ParquetFile(path).metadata.num_rows
    else:
        with path.open(encoding='utf-8') as stream:
            rows = sum(1 for line in stream if line.strip())
    return {'path': path.name, 'format': path.suffix[1:], 'rows': rows,
            'bytes': path.stat().st_size, 'sha256': file_hash(path), 'layout_version': 2}


def read_batch(directory):
    """M2 entry point: validate published marker, contract, counts and checksums."""
    directory = Path(directory).resolve()
    marker = json.loads((directory / 'READY.json').read_text(encoding='utf-8'))
    if file_hash(directory / 'batch.json') != marker['batch_sha256']:
        raise ValueError('Batch manifest checksum mismatch')
    batch = json.loads((directory / 'batch.json').read_text(encoding='utf-8'))
    if batch.get('contract_version') != CONTRACT_VERSION or batch.get('status', {}).get('stage') != 'READY':
        raise ValueError('Unsupported or incomplete SuspiciousEventBatch')
    if batch['run_id'] != marker['run_id']:
        raise ValueError('Run identity mismatch')
    for info in batch['artifact_metadata'].values():
        path = (directory / info['path']).resolve()
        if path.parent != directory:
            raise ValueError('Artifact path escapes batch directory')
        actual = artifact_info(path)
        if any(actual[key] != info[key] for key in ('rows', 'bytes', 'sha256', 'format')):
            raise ValueError('Artifact integrity mismatch: ' + path.name)
    return batch


def iter_suspicious(directory, batch_size=1000):
    """Validate, then stream native dict/list rows; no LLM or external service."""
    batch = read_batch(directory)
    path = Path(directory) / batch['artifacts']['suspicious_events']
    if path.suffix == '.parquet':
        import pyarrow.parquet as pq
        for chunk in pq.ParquetFile(path).iter_batches(batch_size=batch_size):
            yield from chunk.to_pylist()
    else:
        with path.open(encoding='utf-8') as stream:
            for line in stream:
                if line.strip(): yield json.loads(line)
