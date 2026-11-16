#!/usr/bin/env bash
set -u
work=/root/sj-tmp/cqsec_mist8b_web_20261115
printf '%s\n' '--- Filesystem capacity (GiB-style df) ---'
df -hT / /root/sj-tmp /root/sj-fs /tmp
printf '%s\n' '--- Filesystem space in bytes ---'
df -B1 --output=target,size,used,avail / /root/sj-tmp /root/sj-fs /tmp
printf '%s\n' '--- Filesystem mounts ---'
findmnt -T / -o TARGET,SOURCE,FSTYPE,OPTIONS -n
findmnt -T /root/sj-tmp -o TARGET,SOURCE,FSTYPE,OPTIONS -n
findmnt -T /root/sj-fs -o TARGET,SOURCE,FSTYPE,OPTIONS -n
printf '%s\n' '--- Task directory and components ---'
du -h -d 1 "$work" 2>/dev/null | sort -h
du -h -d 1 "$work/models" 2>/dev/null | sort -h
printf '%s\n' '--- Root-side ML caches ---'
for p in /root/.cache/huggingface /root/.cache/pip /root/.cache/torch /root/.cache/modelscope /tmp; do
  if [ -d "$p" ]; then du -sh "$p" 2>/dev/null || true; fi
done
printf '%s\n' '--- Relevant runtime cache settings ---'
for key in HF_HOME HF_DATASETS_CACHE HUGGINGFACE_HUB_CACHE TRANSFORMERS_CACHE TMPDIR XDG_CACHE_HOME; do
  value="${!key:-<unset>}"
  printf '%s=%s\n' "$key" "$value"
done
printf '%s\n' '--- Per-run storage (if present) ---'
du -h -d 2 "$work/runs" 2>/dev/null | sort -h | tail -n 20
