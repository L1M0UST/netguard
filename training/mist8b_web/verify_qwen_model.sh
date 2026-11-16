#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
"$work/env312/bin/python" - "$work/models/Qwen3-8B-ModelScope" <<'PY'
import json,sys
from pathlib import Path
from safetensors import safe_open
from transformers import AutoConfig,AutoTokenizer
p=Path(sys.argv[1]); c=AutoConfig.from_pretrained(p,trust_remote_code=False,local_files_only=True)
t=AutoTokenizer.from_pretrained(p,trust_remote_code=False,local_files_only=True)
index=json.loads((p/'model.safetensors.index.json').read_text())['weight_map']
shards=sorted(set(index.values()))
assert len(shards)==5
all_keys=set()
for name in shards:
 with safe_open(p/name,framework='pt',device='cpu') as f:
  keys=set(f.keys())
 expected={k for k,v in index.items() if v==name}
 assert keys==expected, f'index mismatch in {name}'
 assert all_keys.isdisjoint(keys)
 all_keys.update(keys)
assert all_keys==set(index)
ids=t.encode('请分析这条安全日志。',add_special_tokens=False)
assert ids and max(ids)<c.vocab_size
print('architecture',type(c).__name__,'layers',c.num_hidden_layers,'vocabulary',c.vocab_size)
print('tokenizer_loaded',len(t),'sample_tokens',len(ids))
print('safetensor_shards',len(shards),'index_tensors_verified',len(index))
print('QWEN_MODEL_METADATA_AND_INDEX_VERIFIED')
PY
