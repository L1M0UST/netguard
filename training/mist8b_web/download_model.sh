#!/usr/bin/env bash
set -euo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
model="$work/models/MiST-8B"
revision=9ba377df00b9e830849fce8ebbe568a9a84774f2
repo="https://hf-mirror.com/dreamgroup/MiST-8B"
mkdir -p "$model" "$work/reports"

fetch() {
    local path="$1" mode="$2" dest="$model/$1"
    if [ -f "$dest" ]; then return; fi
    curl -fsSL --retry 8 --retry-all-errors --retry-delay 5 --connect-timeout 20 \
      --speed-time 120 --speed-limit 10000 -C - -o "$dest.partial" \
      "$repo/$mode/$revision/$path"
    mv "$dest.partial" "$dest"
}

for path in LICENSE NOTICE chat_template.jinja config.json generation_config.json tokenizer_config.json; do
    printf 'FETCH %s\n' "$path"
    fetch "$path" raw
done
printf '%s\n' 'FETCH tokenizer.json'
fetch tokenizer.json resolve
printf '%s\n' 'FETCH model.safetensors (16.38 GB)'
fetch model.safetensors resolve
printf '%s\n' 'VERIFY official git blobs and SHA-256'
python - "$model" <<'PY'
from pathlib import Path
import hashlib, sys
p=Path(sys.argv[1])
blobs={
 'LICENSE':'416a35d0305aac8dfdcb5c14637cbcd66fc55b39',
 'NOTICE':'0edae90e52f75a1e796044225c0834db51c01827',
 'chat_template.jinja':'01be9b307daa2d425f7c168c9fb145a286e0afb4',
 'config.json':'034c3977aa8c5ad0246f486161cf30a120c00012',
 'generation_config.json':'17c4d8de4ba93a03b3bb35ab97ad7798e87811e8',
 'tokenizer_config.json':'770e41d6c92519d525eede4cbcf3ba27f6425311',
}
for name, expected in blobs.items():
 data=(p/name).read_bytes(); actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
 if actual!=expected: raise SystemExit('Git blob mismatch: '+name)
 print('verified',name)
for name, expected, size in [
 ('tokenizer.json','be75606093db2094d7cd20f3c2f385c212750648bd6ea4fb2bf507a6a4c55506',11422650),
 ('model.safetensors','f9744f074f62dd44a6031cf5180cd9b0f8926fe1053bce684c700ec7aa98b91f',16381517208),
]:
 f=p/name; h=hashlib.sha256()
 with f.open('rb') as stream:
  for chunk in iter(lambda:stream.read(8*1024*1024),b''): h.update(chunk)
 if f.stat().st_size!=size or h.hexdigest()!=expected: raise SystemExit('SHA-256 mismatch: '+name)
 print('verified',name,size,h.hexdigest())
PY
printf '%s\n' 'MiST-8B 9ba377df00b9e830849fce8ebbe568a9a84774f2 verified' > "$work/reports/model-verified.txt"
printf '%s\n' 'MODEL_DOWNLOAD_VERIFIED'
