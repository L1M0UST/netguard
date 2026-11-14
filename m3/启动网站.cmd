@echo off
cd /d "%~dp0"
title NetGuard local server - keep this window open
echo Open http://127.0.0.1:8001/ in your browser.
echo Keep this window open while using NetGuard.
python -m uvicorn server:app --host 127.0.0.1 --port 8001
pause
