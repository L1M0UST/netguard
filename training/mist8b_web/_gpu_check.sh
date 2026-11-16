#!/usr/bin/env bash
nvidia-smi
echo "== SAMPLES =="
nvidia-smi --query-gpu=utilization.gpu,utilization.memory,memory.used,memory.total,power.draw,power.limit,clocks.sm,clocks.max.sm,temperature.gpu --format=csv,noheader
