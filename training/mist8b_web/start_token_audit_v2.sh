#!/usr/bin/env bash
set -euo pipefail
work=/root/sj-tmp/cqsec_mist8b_web_20261115
test -x "$work/env312/bin/python"
test ! -e "$work/data/web_fit_v2"
nohup "$work/env312/bin/python" -u "$work/audit_tokens_v2.py" > "$work/logs/token_audit_v2.log" 2>&1 < /dev/null &
printf '%s\n' "$!" > "$work/logs/token_audit_v2.pid"
printf 'token audit v2 started pid=%s\n' "$!"
