#!/usr/bin/env bash
set -u
echo "== TTY =="
stty -a 2>/dev/null | head -3
echo "== PY U-C EXEC TEST =="
B64='aW1wb3J0IHN5cw0KcHJpbnQoIl9VUF9SRUFEWV9PS18iLGZsdXNoPVRydWUpDQo='
python -u -c "import base64;exec(base64.b64decode('$B64'))" 2>&1 || echo "u-c exec FAILED rc=$?"
echo "== B64 WRITE TEST =="
printf %s "$B64" | base64 -d > /root/qwen_work/_diag.txt && echo "b64 write ok: $(cat /root/qwen_work/_diag.txt)"
echo "== PATH PYTHON =="
command -v python
echo 'diag end'
