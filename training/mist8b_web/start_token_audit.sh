#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test -x "$work/env312/bin/python"
test ! -e "$work/data/web_fit"
nohup "$work/env312/bin/python" -u "$work/audit_tokens.py" > "$work/logs/token_audit.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/logs/token_audit.pid"
printf 'token audit started pid=%s\n' "$!"
