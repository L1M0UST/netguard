#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf '%s\n' '--- MiST model directory (logical and allocated bytes) ---'
find "$work/models/MiST-8B" -maxdepth 1 -type f -printf '%f\t%k KiB allocated\t%s bytes logical\n' | sort
printf '%s\n' '--- Temporary files/directories, largest 25 ---'
du -h -d 2 "$work/tmp" 2>/dev/null | sort -h | tail -n 25
printf '%s\n' '--- Files >100MB in task temp/cache ---'
find "$work/tmp" "$work/cache" -type f -size +100M -printf '%p\t%s bytes\n' 2>/dev/null | sort
printf '%s\n' '--- Owned setup processes ---'
ps -eo pid,ppid,stat,args | awk -v w="$work" 'index($0,w) && /setup_env|pip install|conda create|download_model|run_pipeline/ && !/awk/ {print}'
printf '%s\n' '--- Model architecture dimensions ---'
python - "$work/models/MiST-8B/config.json" "$work/models/Qwen3-8B-ModelScope/config.json" <<'PY'
import json,sys
for name in sys.argv[1:]:
 x=json.load(open(name))
 print(name, {k:x.get(k) for k in ('vocab_size','hidden_size','intermediate_size','num_hidden_layers','num_attention_heads','num_key_value_heads','head_dim','tie_word_embeddings')})
PY
