#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
cd "$work"
"$work/env312/bin/python" - <<'PY'
from pathlib import Path
import yaml
from llamafactory.hparams import get_train_args
from transformers import AutoTokenizer
from llamafactory.data.template import get_template_and_fix_tokenizer
from llamafactory.data import get_dataset
for filename in ('smoke','profile','round1'):
 config=yaml.safe_load(Path('configs',filename+'.yaml').read_text())
 model_args,data_args,training_args,finetuning_args,generating_args=get_train_args(config)
 print('configuration parsed',filename,'template',data_args.template,
       'quantization_bit',model_args.quantization_bit,'cutoff',data_args.cutoff_len)
 if filename=='smoke':
  tok=AutoTokenizer.from_pretrained(config['model_name_or_path'],local_files_only=True,trust_remote_code=False)
  template=get_template_and_fix_tokenizer(tok,data_args)
  bundle=get_dataset(template,model_args,data_args,training_args,stage='sft',tokenizer=tok)
  sample=bundle['train_dataset'][0]
  assert sample['input_ids'] and len(sample['input_ids'])==len(sample['labels'])
  assert any(value!=-100 for value in sample['labels'])
  print('dataset tokenization and supervised labels verified',len(bundle['train_dataset']),'rows')
print('TRAIN_CONFIGS_DATA_VERIFIED')
PY
