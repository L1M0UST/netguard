"""Run an isolated, offline CSV batch benchmark: python -m tests.benchmark_schema."""
import argparse
import csv
import ctypes
import json
import shutil
import time
from pathlib import Path
from uuid import uuid4

from m1.run import process


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rows', type=int, default=100000)
    args = parser.parse_args()
    root = Path(__file__).parent / '.test-workspaces' / str(uuid4())
    root.mkdir(parents=True)
    try:
        (root / 'incoming').mkdir()
        (root / 'm1').mkdir()
        (root / 'm1/config.json').write_text(json.dumps({'output': {'format': 'parquet', 'require_parquet': True}}))
        with (root / 'incoming/data.csv').open('w', newline='', encoding='utf-8') as stream:
            writer = csv.writer(stream)
            writer.writerow(['Source IP', 'Destination', 'Time', 'URL', 'Payload'])
            for index in range(args.rows):
                writer.writerow(['10.0.0.1', '10.0.0.2', '2026-01-01T00:00:00Z', f'/item/{index}', 'example'])
        manifest = root / 'manifest.json'
        manifest.write_text(json.dumps({'task_id': 'benchmark', 'input_files': ['incoming/data.csv']}))
        start = time.perf_counter()
        ready = process(root, manifest)
        elapsed = time.perf_counter() - start
        status = json.loads((ready / 'status.json').read_text(encoding='utf-8'))
        report = {'input_rows': args.rows, 'elapsed_seconds': round(elapsed, 2), 'metrics': status['metrics'], 'llm_calls': status['llm_calls'], 'note': 'Synthetic short-payload CSV, LLM and online intelligence disabled; includes Parquet output.'}
        if hasattr(ctypes, 'windll'):
            class MemoryCounters(ctypes.Structure):
                _fields_ = [('cb', ctypes.c_ulong), ('PageFaultCount', ctypes.c_ulong)] + [(name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize', 'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage')]
            counters = MemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(handle), ctypes.byref(counters), counters.cb):
                report['peak_working_set_mib'] = round(counters.PeakWorkingSetSize / 1024**2, 1)
        target = Path(__file__).parent / 'schema_benchmark_result.json'
        target.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(json.dumps(report))
    finally:
        shutil.rmtree(root)


if __name__ == '__main__':
    main()
