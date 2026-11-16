"""Watch queued MiST work and retrieve checksummed artifacts when available."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import re
import time
from pathlib import Path

from remote_client import connect, download, run_script

WORK='/root/sj-tmp/cqsec_mist8b_web_20261115'
OUT=Path(r'E:\platform_taishi\mist8b-web-data')
STATUS=OUT/'mist8b-vllm-status.txt'
SNAPSHOT=f'''set -u
work={WORK}
for key in qwen_vllm_pipeline mist_after_qwen mist_checkpoint_monitor; do
  printf '%s=' "$key"
  cat "$work/reports/${{key}}_state.txt" 2>/dev/null || echo unavailable
done
for item in adapter vllm; do
  printf 'sha_%s=' "$item"
  cat "$work/exports/mist8b-web-stage1-${{item}}.sha256" 2>/dev/null || echo pending
done
'''


def write_status(lines:list[str])->None:
    now=datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    STATUS.write_text('\n'.join([f'updated={now}',*lines])+'\n',encoding='utf-8')
    print(now,' | '.join(lines),flush=True)


def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for part in iter(lambda:f.read(4*1024*1024),b''):h.update(part)
    return h.hexdigest()


def main()->None:
    ap=argparse.ArgumentParser();ap.add_argument('--once',action='store_true');args=ap.parse_args()
    OUT.mkdir(parents=True,exist_ok=True);end=time.monotonic()+72*3600
    while time.monotonic()<end:
        client=None
        try:
            client,channel,_,_=connect()
            output,code=run_script(channel,SNAPSHOT,30)
            if code!=0:raise RuntimeError('remote snapshot failed')
            fields=dict(re.findall(r'(?:^|[\r\n])(qwen_vllm_pipeline|mist_after_qwen|mist_checkpoint_monitor|sha_adapter|sha_vllm)=([^\r\n]*)',output))
            lines=[f'{k}={v}' for k,v in fields.items()];done=0
            for kind in ('adapter','vllm'):
                expected=fields.get('sha_'+kind,'')
                if not re.fullmatch(r'[0-9a-f]{64}',expected):continue
                filename='mist8b-web-stage1-'+kind+'.zip';target=OUT/filename
                if not target.exists():
                    write_status(lines+[f'downloading={filename}'])
                    download(channel,WORK+'/exports/'+filename,target,7200)
                if sha256(target)!=expected:raise RuntimeError('downloaded archive checksum mismatch')
                lines.append(f'downloaded_{kind}={target}');done+=1
            write_status(lines)
            if done==2:return
        except Exception as exc:
            write_status(['monitor_retry='+type(exc).__name__])
        finally:
            if client:client.close()
        if args.once:return
        time.sleep(90)
    write_status(['monitor_timeout=72h'])


if __name__=='__main__':main()
