"""Download the official Qwen3-8B snapshot and verify each official SHA-256."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import time
import urllib.parse
import urllib.request

WORK = Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
DEST = WORK / 'models/Qwen3-8B-ModelScope'
REV = '26028140be3ee69b82b1d1450179ab71bb1121b9'
BASE = 'https://www.modelscope.cn/api/v1/models/Qwen/Qwen3-8B/repo'
TOTAL = 16397461896
MIST_TOTAL = 16381517208
SHARD1_SHA = '31d6a825ae35f11fb85b195b4c42c146c051e446433125a215336abdf95cbf5f'


def digest(path: Path) -> str:
    result=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(8*1024*1024),b''):
            result.update(chunk)
    return result.hexdigest()


def main() -> None:
    started=time.monotonic()
    url=BASE+'/files?'+urllib.parse.urlencode({'Revision':REV,'Recursive':'true'})
    with urllib.request.urlopen(url,timeout=30) as response:
        result=json.load(response)
    if not result.get('Success'):
        raise RuntimeError('ModelScope manifest request failed')
    files=[x for x in result['Data']['Files'] if x.get('Type')=='blob']
    if sum(f['Size'] for f in files)!=TOTAL:
        raise RuntimeError('unexpected pinned snapshot size')
    if next(f['Sha256'] for f in files if f['Path']=='model-00001-of-00005.safetensors')!=SHARD1_SHA:
        raise RuntimeError('unexpected first shard digest')
    for f in files:
        path=PurePosixPath(f['Path'])
        if path.is_absolute() or len(path.parts)!=1 or '..' in path.parts:
            raise ValueError('unexpected repository file path')
        if len(f['Sha256'])!=64:
            raise ValueError('invalid file digest')
    DEST.mkdir(parents=True,exist_ok=True)
    remaining=sum(max(0,f['Size']-(DEST/(f['Path']+'.partial')).stat().st_size)
                  for f in files if not (DEST/f['Path']).is_file()
                  and (DEST/(f['Path']+'.partial')).exists())
    remaining+=sum(f['Size'] for f in files if not (DEST/f['Path']).is_file()
                   and not (DEST/(f['Path']+'.partial')).exists())
    mist_partial=WORK/'models/MiST-8B/model.safetensors.partial'
    mist_final=WORK/'models/MiST-8B/model.safetensors'
    mist_remaining=0 if mist_final.exists() else max(0,MIST_TOTAL-(mist_partial.stat().st_size if mist_partial.exists() else 0))
    if shutil.disk_usage(WORK).free < remaining+mist_remaining+6*1024**3:
        raise RuntimeError('insufficient disk space for both models and 6 GiB training reserve')
    manifest={'repository':'Qwen/Qwen3-8B','revision':REV,'total_bytes':TOTAL,'files':files}
    manifest_path=WORK/'reports/qwen3_modelscope_manifest.json'
    if manifest_path.exists():
        old=json.loads(manifest_path.read_text())
        if old['revision']!=REV or old['total_bytes']!=TOTAL:
            raise RuntimeError('existing manifest differs')
    else:
        manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    # Small metadata first; large shard transfers remain individually resumable.
    files.sort(key=lambda f:(f['Size']>100*1024*1024,f['Path']))
    received=0
    for index,f in enumerate(files,1):
        target=DEST/f['Path']
        partial=DEST/(f['Path']+'.partial')
        if not target.exists():
            initial=partial.stat().st_size if partial.exists() else 0
            file_url=BASE+'?'+urllib.parse.urlencode({'Revision':REV,'FilePath':f['Path']})
            tick=time.monotonic()
            print(f'[{index}/{len(files)}] downloading {f["Path"]}, resume={initial}, bytes={f["Size"]}',flush=True)
            subprocess.run(['curl','-fsSL','--retry','8','--retry-all-errors','--retry-delay','5',
                '--connect-timeout','20','--speed-time','120','--speed-limit','10000',
                '-C','-','-o',str(partial),file_url],check=True)
            received+=partial.stat().st_size-initial
            elapsed=max(time.monotonic()-tick,.01)
            print(f'downloaded {f["Path"]} in {elapsed:.1f}s at {(partial.stat().st_size-initial)/elapsed/1e6:.2f} MB/s',flush=True)
            if partial.stat().st_size!=f['Size'] or digest(partial)!=f['Sha256']:
                raise RuntimeError('file size or SHA-256 mismatch: '+f['Path'])
            os.rename(partial,target)
        else:
            if target.stat().st_size!=f['Size'] or digest(target)!=f['Sha256']:
                raise RuntimeError('existing file size or SHA-256 mismatch: '+f['Path'])
        print('verified',f['Path'],flush=True)
    duration=time.monotonic()-started
    report={'model':'Qwen/Qwen3-8B','source':'ModelScope','revision':REV,
            'snapshot_bytes':TOTAL,'downloaded_this_run_bytes':received,'seconds':duration,
            'all_files_sha256_verified':True,'model_dir':str(DEST)}
    (WORK/'reports/qwen3_download.json').write_text(json.dumps(report,indent=2)+'\n')
    print('QWEN_DOWNLOAD_VERIFIED',json.dumps(report),flush=True)


if __name__=='__main__':
    main()
