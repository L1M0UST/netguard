#!/usr/bin/env bash
set -euo pipefail
umask 077
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
export TOKENIZERS_PARALLELISM=false
export WANDB_DISABLED=true
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export CUDA_VISIBLE_DEVICES=0
py="$work/env312/bin/python"
test ! -e "$work/models/probe-random-qwen3-v2"
test ! -e "$work/runs/infra_probe_v2"
"$py" - <<'PY'
import json
from pathlib import Path
import torch,yaml
from transformers import Qwen3Config,Qwen3ForCausalLM
work=Path('/root/sj-tmp/cqsec_mist8b_web_20261115')
dst=work/'models/probe-random-qwen3-v2'
dst.mkdir()
torch.manual_seed(42)
config=Qwen3Config(vocab_size=151936,hidden_size=128,intermediate_size=256,
  num_hidden_layers=2,num_attention_heads=4,num_key_value_heads=2,head_dim=32,
  max_position_embeddings=2048,tie_word_embeddings=True)
Qwen3ForCausalLM(config).save_pretrained(dst,safe_serialization=True)
src=work/'models/MiST-8B-transformers4'
for name in ('tokenizer.json','tokenizer_config.json','chat_template.jinja'):
 (dst/name).symlink_to(src/name)
cfg=yaml.safe_load((work/'configs/smoke.yaml').read_text())
cfg.update({'model_name_or_path':str(dst),'max_steps':2,'max_samples':8,
            'gradient_accumulation_steps':1,'cutoff_len':512,
            'output_dir':str(work/'runs/infra_probe_v2'),'save_steps':2})
(work/'configs/infra_probe_v2.yaml').write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False))
print('created tiny RANDOM architecture; infrastructure probe only')
PY
"$work/env312/bin/llamafactory-cli" train "$work/configs/infra_probe_v2.yaml" > "$work/logs/infra_probe_v2.log" 2>&1
test -f "$work/runs/infra_probe_v2/adapter_config.json"
printf 'RANDOM_MODEL_INFRASTRUCTURE_PROBE_PASSED\n'
