#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
echo "== HOST =="
hostname; date -u '+%F %T UTC'; uname -srm; nproc
echo "== MEM =="
free -g | head -3
echo "== GPU =="
nvidia-smi --query-gpu=name,driver_version,memory.total,memory.used,utilization.gpu,temperature.gpu --format=csv,noheader
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader
echo "== NVCC =="
(nvcc --version | tail -2) 2>/dev/null || echo "nvcc: not found"
echo "== DISK =="
df -h /root /root/sj-tmp 2>/dev/null
echo "== WORKDIR =="
ls -la "$work" 2>/dev/null | head -50
echo "== MODELS =="
du -sh "$work"/models/* 2>/dev/null
echo "== ENV PY =="
"$work"/env312/bin/python -V 2>/dev/null || echo "env312 missing"
"$work"/env312/bin/python - <<'PY' 2>/dev/null
import importlib
for m in ("torch","transformers","peft","trl","datasets","accelerate","bitsandbytes","llamafactory","safetensors","pyarrow","tokenizers"):
    try:
        mod=importlib.import_module(m); print(m, getattr(mod,"__version__","?"))
    except Exception as e: print(m,"MISSING",type(e).__name__)
try:
    import torch; print("cuda_available",torch.cuda.is_available(),"devices",torch.cuda.device_count(),"cap",torch.cuda.get_device_capability(0) if torch.cuda.is_available() else None)
except Exception as e: print("torch_check_failed",e)
PY
echo "== LLAMAFACTORY =="
"$work"/env312/bin/llamafactory-cli version 2>&1 | head -3
echo "== DATA =="
for d in "$work"/data/*; do echo "-- $d"; ls -la "$d" 2>/dev/null | head -10; done
wc -l "$work"/data/web_fit_v2/*.jsonl 2>/dev/null
echo "== REPORTS =="
ls -la "$work"/reports 2>/dev/null | head -30
echo "== LOG TAILS =="
tail -n 5 "$work"/logs/download_model.log 2>/dev/null
echo "== DOWNLOAD SPEED (30s) =="
f="$work/models/MiST-8B/model.safetensors.partial"
if [ -f "$f" ]; then a=$(stat -c %s "$f"); sleep 30; b=$(stat -c %s "$f"); echo "delta_bytes=$((b-a)) speed_MBps=$(awk -v d=$((b-a)) 'BEGIN{printf "%.2f", d/30/1048576}') now=$b"; else echo "no partial"; fi
echo "== PIPELINE =="
cat "$work"/reports/pipeline-state.txt 2>/dev/null
ps -p "$(cat "$work"/pipeline.pid 2>/dev/null)" -o pid=,stat=,etime=,args= 2>/dev/null
ps -p "$(cat "$work"/download.pid 2>/dev/null)" -o pid=,stat=,etime=,args= 2>/dev/null
echo "== TOKENIZER COMPAT =="
ls -la "$work"/models/MiST-8B-transformers4 2>/dev/null | head -20
cat "$work"/models/MiST-8B-transformers4/COMPATIBILITY.json 2>/dev/null | head -40
echo "== NET =="
curl -s -o /dev/null -w "modelscope %{http_code} %{time_total}s\n" --max-time 10 https://www.modelscope.cn/ 2>&1
