#!/usr/bin/env bash
set -euo pipefail
root=/root/qwen3-vllm-085/lib/python3.12/site-packages/vllm
grep -n -A 88 'def determine_available_memory' "$root/v1/worker/gpu_worker.py" | head -100
grep -n -A 85 'def memory_profiling' "$root/utils.py" | head -90
