#!/usr/bin/env bash
echo "== ADDRS =="
ip -4 addr show | grep -E "inet " 
echo "== PUBLIC IP VIA OUTBOUND =="
timeout 8 curl -s ifconfig.me 2>/dev/null || echo "(outbound probe blocked)"
echo
echo "== LISTENING NOW =="
ss -tlnp 2>/dev/null | head -15
echo "== FIREWALL =="
(nft list ruleset 2>/dev/null | head -20) || true
(iptables -L -n 2>/dev/null | head -20) || true
echo "== START TEST LISTENERS 8080/7899 (180s) =="
pkill -f "http.server 8080" 2>/dev/null; pkill -f "http.server 7899" 2>/dev/null
nohup timeout 180 python3 -m http.server 8080 --bind 0.0.0.0 >/tmp/h8080.log 2>&1 &
echo "8080 pid $!"
nohup timeout 180 python3 -m http.server 7899 --bind 0.0.0.0 >/tmp/h7899.log 2>&1 &
echo "7899 pid $!"
sleep 1
curl -s -o /dev/null -w "local 8080: %{http_code}\n" http://127.0.0.1:8080/
curl -s -o /dev/null -w "local 7899: %{http_code}\n" http://127.0.0.1:7899/
