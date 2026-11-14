@echo off
REM M3 BFF 启动脚本（供后台运行使用，绝对路径避免 127 错误）
set NETGUARD_WORKSPACE=E:/platform_taishi/taishi_platform/workspace
set NETGUARD_DATA_DIR=E:/platform_taishi/taishi_platform/m3/data
set NETGUARD_LLM_ENABLED=1
set NETGUARD_LLM_PROTOCOL=cqsec
set CQSEC_BASE_URL=http://127.0.0.1:8008
E:/platform_taishi/taishi_platform/.venv/Scripts/python.exe -m uvicorn server:app --host 127.0.0.1 --port 8001
