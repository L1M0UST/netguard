#!/usr/bin/env bash
set -eu
ps -eo pid,ppid,stat,args | awk '/relay_receiver.py|download_model.sh/ && !/awk/ {print}'
