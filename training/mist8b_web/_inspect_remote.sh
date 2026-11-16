#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
echo "== DATASET_INFO =="; cat "$work"/data/web_fit_v2/dataset_info.json
echo "== DATA DIRS =="; ls -la "$work"/data
echo "== RUNS =="; find "$work"/runs -maxdepth 2 -type f | head -30; du -sh "$work"/runs/*
echo "== REPORTS =="; ls -la "$work"/reports
echo "== CONFIGS =="; for f in "$work"/configs/*; do echo "--- $f"; cat "$f"; done
echo "== QWEN CONFIG =="; cat "$work"/models/Qwen3-8B-ModelScope/config.json
echo "== TEMPLATE =="; grep -rn "qwen3_nothink" "$work"/env312/lib/python3.12/site-packages/llamafactory/data/template.py | head -5
echo "== EVAL SCRIPT =="
cat "$work"/evaluate_web.py
