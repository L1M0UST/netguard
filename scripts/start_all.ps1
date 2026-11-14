$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$contestRoot = 'E:\code\2026年第二届重庆市AI大模型创新应用大赛'
$python = Join-Path $root '.venv\Scripts\python.exe'
$modelExe = Join-Path $contestRoot 'tools\llamacpp\bin\llama-server.exe'
$modelFile = 'E:\cqwork\gguf\qwen3-4b-cqsec-v32-Q4_K_M.gguf'
$logs = Join-Path $root 'logs'
New-Item -ItemType Directory -Path $logs -Force | Out-Null

function Test-LocalPort([int]$port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try { $client.Connect('127.0.0.1', $port); return $true }
    catch { return $false }
    finally { $client.Dispose() }
}

if (-not (Test-LocalPort 8008)) {
    if ((Test-Path -LiteralPath $modelExe) -and (Test-Path -LiteralPath $modelFile)) {
        Write-Host '[1/3] 启动本地模型 API：127.0.0.1:8008'
        $modelLog = Join-Path $contestRoot 'logs_model_api.log'
        $modelProcess = Start-Process -FilePath $modelExe -ArgumentList @('-m', $modelFile, '--host', '127.0.0.1', '--port', '8008', '-ngl', '99', '-c', '8192', '-np', '4', '-fa', 'on', '--threads', '6') -WorkingDirectory $contestRoot -WindowStyle Hidden -RedirectStandardOutput $modelLog -RedirectStandardError (Join-Path $contestRoot 'logs_model_api_error.log') -PassThru
        [System.IO.File]::WriteAllText((Join-Path $logs 'model-8008.pid'), [string]$modelProcess.Id)
    } else {
        Write-Host '[1/3] 本地模型文件未找到；将使用配置的模型提供方或本地降级。'
    }
} else { Write-Host '[1/3] 本地模型 API 已运行：127.0.0.1:8008' }

$env:NETGUARD_WORKSPACE = Join-Path $root 'workspace'
$env:NETGUARD_LLM_ENABLED = '1'
$env:NETGUARD_LLM_PROTOCOL = 'cqsec'
$env:PYTHONUTF8 = '1'
if (-not (Test-Path -LiteralPath $python)) { throw "找不到项目 Python 环境：$python" }

if (-not (Test-LocalPort 8001)) {
    Write-Host '[2/3] 启动 NetGuard 服务：http://127.0.0.1:8001'
    $m3Process = Start-Process -FilePath $python -ArgumentList @('-m', 'uvicorn', 'server:app', '--host', '127.0.0.1', '--port', '8001') -WorkingDirectory (Join-Path $root 'm3') -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logs 'm3-8001.log') -RedirectStandardError (Join-Path $logs 'm3-8001-error.log') -PassThru
    [System.IO.File]::WriteAllText((Join-Path $logs 'm3-8001.pid'), [string]$m3Process.Id)
    $deadline = (Get-Date).AddSeconds(20)
    while (-not (Test-LocalPort 8001) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-LocalPort 8001)) { throw 'NetGuard 服务未能在 8001 端口启动；请查看 logs/m3-8001-error.log' }
} else { Write-Host '[2/3] NetGuard 服务已运行：127.0.0.1:8001' }

$orchestrator = Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -match 'orchestrator\.driver watch' }
if (-not $orchestrator) {
    Write-Host '[3/3] 启动分析编排器'
    $orchestratorProcess = Start-Process -FilePath $python -ArgumentList @('-m', 'orchestrator.driver', 'watch') -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logs 'orchestrator-console.log') -RedirectStandardError (Join-Path $logs 'orchestrator-console-error.log') -PassThru
    [System.IO.File]::WriteAllText((Join-Path $logs 'orchestrator-watch.pid'), [string]$orchestratorProcess.Id)
} else { Write-Host '[3/3] 分析编排器已运行' }

Write-Host ''
Write-Host '启动完成：http://127.0.0.1:8001'
Write-Host '统一入口会启动 NetGuard、分析编排器及可用的本地模型；不会启动测试 UI 或外网隧道。'
