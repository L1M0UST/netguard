#!/usr/bin/env bash
set -euo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
src="$work/models/MiST-8B"
dst="$work/models/MiST-8B-transformers4"
test ! -e "$dst"
mkdir "$dst"
for name in LICENSE NOTICE chat_template.jinja config.json generation_config.json tokenizer.json; do
  ln -s "$src/$name" "$dst/$name"
done
ln -s "$src/model.safetensors" "$dst/model.safetensors"
"$work/env312/bin/python" - "$src" "$dst" <<'PY'
import json,sys
from pathlib import Path
from tokenizers import Tokenizer
from transformers import AutoTokenizer
src,dst=map(Path,sys.argv[1:])
config=json.loads((src/'tokenizer_config.json').read_text(encoding='utf-8'))
extra=config.pop('extra_special_tokens')
assert isinstance(extra,list) and all(isinstance(x,str) for x in extra)
config['additional_special_tokens']=extra
(dst/'tokenizer_config.json').write_text(json.dumps(config,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
raw=Tokenizer.from_file(str(src/'tokenizer.json'))
tok=AutoTokenizer.from_pretrained(dst,local_files_only=True,trust_remote_code=False)
for token in extra:
 assert raw.token_to_id(token)==tok.convert_tokens_to_ids(token), token
 assert len(tok.encode(token,add_special_tokens=False))==1, token
print('all',len(extra),'extra special token IDs agree with the original tokenizer.json')
print('eos',tok.eos_token,tok.eos_token_id,'pad',tok.pad_token,tok.pad_token_id,'vocabulary',len(tok))
print('model type',json.loads((src/'config.json').read_text())['model_type'])
(dst/'COMPATIBILITY.json').write_text(json.dumps({
 'source_revision':'9ba377df00b9e830849fce8ebbe568a9a84774f2',
 'change':'tokenizer_config extra_special_tokens list renamed to transformers4 additional_special_tokens',
 'special_token_ids_checked':len(extra),'weights_unchanged':True,
 'original_config_preserved':True},indent=2)+'\n')
PY
