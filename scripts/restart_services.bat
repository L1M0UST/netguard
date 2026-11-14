@echo off
REM NetGuard 服务一键重启：先杀净旧实例（venv 启动器与其基础解释器子进程成对，
REM 一律按命令行匹配杀掉），再以正确环境变量启动 M3(8001) 与编排器。
REM 直接双击运行即可；服务窗口会保持打开（关闭即停止对应服务）。
chcp 65001 >nul
setlocal
set "ROOT=%~dp0.."

echo [1/3] 清理旧进程 ...
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' -and ($_.CommandLine -match 'uvicorn server:app|orchestrator.driver watch') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
timeout /t 2 /nobreak >nul

echo [2/3] 启动 M3 BFF (http://127.0.0.1:8001) ...
set "NETGUARD_WORKSPACE=%ROOT%\workspace"
set "NETGUARD_LLM_ENABLED=1"
set "NETGUARD_LLM_PROTOCOL=cqsec"
start "taishi_m3" cmd /k "cd /d "%ROOT%\m3" && "%ROOT%\.venv\Scripts\python.exe" -m uvicorn server:app --host 127.0.0.1 --port 8001"

echo [3/3] 启动编排器 ...
start "taishi_orchestrator" cmd /k "cd /d "%ROOT%" && ".venv\Scripts\python.exe" -m orchestrator.driver watch"

timeout /t 6 /nobreak >nul
echo.
echo 已启动：M3 网关 http://127.0.0.1:8001　编排器 watch（各自独立窗口，关窗即停）
endlocal
