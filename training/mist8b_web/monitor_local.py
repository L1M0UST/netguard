"""Watch the isolated job and retrieve its checked adapter archive when ready."""
from __future__ import annotations

import datetime
import re
import time
from pathlib import Path

from remote_client import connect, download, run_script

WORK = '/root/sj-tmp/cqsec_mist8b_web_20261115'
OUT = Path(r'E:\platform_taishi\mist8b-web-data')
TARGET = OUT / 'mist8b-web-round1.zip'
STATUS = OUT / 'training-status.txt'
SNAPSHOT = f'''set -u
work={WORK}
printf 'STATE='
cat "$work/reports/pipeline-state.txt" 2>/dev/null || echo unavailable
printf 'PARTIAL_BYTES='
stat -c %s "$work/models/MiST-8B/model.safetensors.partial" 2>/dev/null || echo 0
printf 'PIPELINE_ALIVE='
pid=$(cat "$work/pipeline.pid" 2>/dev/null || true)
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && [ "$(ps -o stat= -p "$pid" | cut -c1)" != Z ]; then echo yes; else echo no; fi
printf 'EXPORT_SHA='
cat "$work/exports/mist8b-web-round1.sha256" 2>/dev/null || echo pending
'''
RESUME_WAITING = f'''set -euo pipefail
work={WORK}
test "$(cat "$work/reports/pipeline-state.txt")" = waiting_for_verified_model
for entry in 'pipeline:run_pipeline_v2.sh' 'report_monitor:report_monitor.sh' 'export_monitor:export_monitor.sh'; do
  name=${{entry%%:*}}
  script=${{entry#*:}}
  file="$work/$name.pid"
  pid=$(cat "$file" 2>/dev/null || true)
  if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ] && tr '\\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$work/$script"; then continue; fi
  nohup bash "$work/$script" >> "$work/logs/$name.log" 2>&1 < /dev/null &
  printf '%s\\n' "$!" > "$file"
  printf 'resumed %s pid=%s\\n' "$name" "$!"
done
'''


def write_status(text: str) -> None:
    timestamp = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    STATUS.write_text(f'updated={timestamp}\n{text}\n', encoding='utf-8')
    print(timestamp, text.replace('\n',' | '), flush=True)


def main() -> None:
    started = time.monotonic()
    while time.monotonic()-started < 48*3600:
        client = None
        try:
            client, channel, _, _ = connect()
            output, exit_code = run_script(channel, SNAPSHOT, 30)
            if exit_code != 0:
                raise RuntimeError('remote snapshot failed')
            fields = dict(re.findall(r'(?:^|[\r\n])(STATE|PARTIAL_BYTES|PIPELINE_ALIVE|EXPORT_SHA)=([^\r\n]*)', output))
            state = fields.get('STATE', 'unavailable')
            write_status('\n'.join(f'{key}={value}' for key,value in fields.items()))
            if re.fullmatch(r'[0-9a-f]{64}', fields.get('EXPORT_SHA','')):
                if not TARGET.exists():
                    download(channel, WORK+'/exports/mist8b-web-round1.zip', TARGET, 3600)
                import hashlib
                digest = hashlib.sha256()
                with TARGET.open('rb') as stream:
                    for chunk in iter(lambda:stream.read(4*1024*1024),b''):
                        digest.update(chunk)
                if digest.hexdigest() != fields['EXPORT_SHA']:
                    raise RuntimeError('export archive digest mismatch')
                write_status('STATE=complete_and_downloaded\nARCHIVE='+str(TARGET)+'\nSHA256='+digest.hexdigest())
                return
            if state.startswith(('pipeline_failed','download_failed','gpu_already_in_use')):
                write_status('STATE='+state+'\nACTION=inspect remote pipeline logs')
                return
            if fields.get('PIPELINE_ALIVE') == 'no' and state == 'waiting_for_verified_model':
                resumed, code = run_script(channel, RESUME_WAITING, 30)
                if code != 0:
                    raise RuntimeError('could not resume waiting pipeline')
                write_status('STATE=waiting_for_verified_model\nACTION=resumed background jobs')
            elif fields.get('PIPELINE_ALIVE') == 'no' and state not in ('complete','unavailable'):
                write_status('STATE='+state+'\nACTION=pipeline stopped; inspect before restarting')
                return
        except Exception as exc:
            write_status('STATE=monitor_retry\nERROR='+type(exc).__name__)
        finally:
            if client:
                client.close()
        time.sleep(60)
    write_status('STATE=monitor_timeout\nACTION=check remote job manually')


if __name__ == '__main__':
    main()
