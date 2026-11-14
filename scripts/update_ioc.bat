@echo off
REM 更新 M1 本地 IOC 库（Spamhaus DROP + OpenPhish，需要外网；失败时设置代理）
REM set HTTP_PROXY=http://127.0.0.1:7890
REM set HTTPS_PROXY=http://127.0.0.1:7890
cd /d %~dp0..
.venv\Scripts\python.exe -m m1.local_ioc --workspace workspace
echo.
echo 导出真实情报到 M2 威胁情报目录...
.venv\Scripts\python.exe -m bridge.export_intel --m1-workspace workspace --intel-dir data\threat_intel
pause
