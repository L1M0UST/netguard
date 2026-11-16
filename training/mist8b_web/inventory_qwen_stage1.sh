#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
echo "== HOST =="; hostname; date -u '+%F %T UTC'; uname -srm; nproc
echo "== MEM =="; free -g | head -3
echo "== GPU =="; nvidia-smi --query-gpu=name,driver_version,memory.total,memory.used,utilization.gpu --format=csv,noheader
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader
echo "== DISK =="; df -h /root /root/sj-tmp
echo "== WORKDIR =="; ls -la "$work"
echo "== MODELS =="
for d in "$work"/models/*; do [ -e "$d" ] || continue; echo "-- $d"; du -sh "$d"; ls -la "$d" | head -25; done
echo "== QWEN REPORT =="; cat "$work/reports/qwen3_download.json" 2>/dev/null
echo "== ENV =="
for py in "$work"/env312/bin/python "$work"/env312/bin/python3 python3; do
  if [ -x "$py" ]; then echo "-- $py"; "$py" -V; fi
done
"$work"/env312/bin/python - <<'PY' 2>/dev/null
import importlib
for m in ("torch","transformers","peft","trl","datasets","accelerate","bitsandbytes","llamafactory","safetensors","pyarrow","tokenizers","modelscope"):
    try:
        mod=importlib.import_module(m); print(m, getattr(mod,"__version__","?"))
    except Exception as e: print(m,"MISSING",type(e).__name__)
try:
    import torch; print("cuda",torch.cuda.is_available(),"n",torch.cuda.device_count(),"bf16",torch.cuda.is_bf16_supported() if torch.cuda.is_available() else None)
except Exception as e: print("torch_check_failed",e)
PY
echo "== LLAMAFACTORY CLI =="
"$work"/env312/bin/llamafactory-cli version 2>&1 | head -5
echo "== DATA =="
wc -l "$work"/data/web_fit_v2/*.jsonl 2>/dev/null
ls -la "$work"/data/web_fit_v2 2>/dev/null
echo "== REPORT v4 =="
head -c 3000 "$work"/reports/data_report_v4.json 2>/dev/null
echo
echo "== SAMPLE TRAIN =="
head -c 1600 "$work"/data/web_fit_v2/train.jsonl 2>/dev/null
echo
echo "== PROCS =="
ps aux | grep -E "download_model|python .*download|llamafactory|train" | grep -v grep
echo "== FREE SPACE BREAKDOWN =="
du -sh "$work"/* 2>/dev/null | sort -h | tail -15
