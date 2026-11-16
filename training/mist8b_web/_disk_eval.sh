#!/usr/bin/env bash
set -u
echo "== DF =="
df -h / /root /root/sj-tmp /tmp /dev/shm 2>/dev/null
echo "== MOUNTS =="
mount | grep -E "on / |vg-lv|overlay" | head -10
echo "== LSBLK =="
lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT 2>/dev/null | head -20
echo "== ROOT WRITE TEST (1GB) =="
mkdir -p /root/qwen_work
if dd if=/dev/zero of=/root/qwen_work/_probe.bin bs=1M count=1024 oflag=direct 2>/dev/null; then
  echo "direct write ok"
else
  dd if=/dev/zero of=/root/qwen_work/_probe.bin bs=1M count=1024 2>&1 | tail -2
fi
rm -f /root/qwen_work/_probe.bin
echo "== INODES =="
df -i / /root/sj-tmp | head -3
echo "== CURRENT WORKSPACE SIZE =="
du -sh /root/sj-tmp/cqsec_mist8b_web_20261115/{models,cache,data,tmp,env312} 2>/dev/null
echo "== MIST DOWNLOAD NOW =="
stat -c '%s' /root/sj-tmp/cqsec_mist8b_web_20261115/models/MiST-8B/model.safetensors.partial 2>/dev/null
