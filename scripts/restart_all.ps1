param([switch]$Yes, [switch]$WhatIf)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$logs = Join-Path $root 'logs'
$contestRoot = 'E:\code\2026年第二届重庆市AI大模型创新应用大赛'
$modelExe = Join-Path $contestRoot 'tools\llamacpp\bin\llama-server.exe'
$modelFile = 'E:\cqwork\gguf\qwen3-4b-cqsec-v32-Q4_K_M.gguf'
$pidFiles = @{
    'model-8008' = Join-Path $logs 'model-8008.pid'
    'm3-8001' = Join-Path $logs 'm3-8001.pid'
    'orchestrator-watch' = Join-Path $logs 'orchestrator-watch.pid'
}

New-Item -ItemType Directory -Path $logs -Force | Out-Null

function Get-ServiceKind($processInfo) {
    if (-not $processInfo) { return $null }
    $command = [string]$processInfo.CommandLine
    if ($processInfo.Name -eq 'python.exe' -and
        $command -match '(?i)(?:^|\s)-m\s+uvicorn\s+server:app(?:\s|$)' -and
        $command -match '(?i)--port\s+8001(?:\s|$)') { return 'm3-8001' }
    if ($processInfo.Name -eq 'python.exe' -and
        $command -match '(?i)(?:^|\s)-m\s+orchestrator\.driver\s+watch(?:\s|$)') { return 'orchestrator-watch' }
    if ($processInfo.Name -eq 'llama-server.exe' -and
        [string]$processInfo.ExecutablePath -ieq $modelExe -and
        $command.Replace('/', '\').Contains($modelFile.Replace('/', '\')) -and
        $command -match '(?i)--port\s+8008(?:\s|$)') { return 'model-8008' }
    return $null
}

if (-not $Yes -and -not $WhatIf) {
    Write-Host '即将重启本项目的 M3(8001)、本地模型(8008)和分析编排器。正在运行的分析任务会被中断。'
    $answer = Read-Host '输入 Y 继续'
    if ($answer -notin @('Y', 'y')) { Write-Host '已取消。'; exit 0 }
}

$processes = @(Get-CimInstance Win32_Process)
$targets = @{}

# 优先使用启动器记录的 PID；进程命令行不匹配时将其视为过期 PID，不会终止它。
foreach ($entry in $pidFiles.GetEnumerator()) {
    $pidFile = $entry.Value
    if (-not (Test-Path -LiteralPath $pidFile)) { continue }
    $savedPid = 0
    $pidText = (Get-Content -LiteralPath $pidFile -Raw).Trim()
    if ([int]::TryParse($pidText, [ref]$savedPid)) {
        $processInfo = $processes | Where-Object { $_.ProcessId -eq $savedPid } | Select-Object -First 1
        if ($processInfo -and (Get-ServiceKind $processInfo) -eq $entry.Key) {
            $targets[[int]$processInfo.ProcessId] = $entry.Key
        }
    }
}

# 兼容旧启动方式：只接管本机对应端口的监听进程，并再次验证其命令行。
foreach ($portInfo in @(@{ Port = 8001; Kind = 'm3-8001' }, @{ Port = 8008; Kind = 'model-8008' })) {
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $portInfo.Port -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -in @('127.0.0.1', '0.0.0.0', '::1', '::') })
    foreach ($listener in $listeners) {
        $processInfo = $processes | Where-Object { $_.ProcessId -eq $listener.OwningProcess } | Select-Object -First 1
        $kind = Get-ServiceKind $processInfo
        if ($kind -ne $portInfo.Kind) {
            throw "端口 $($portInfo.Port) 被非本项目进程占用；为避免误停其他程序，已中止重启。PID=$($listener.OwningProcess)"
        }
        $targets[[int]$processInfo.ProcessId] = $kind
    }
}

# 兼容旧版启动器：先找本项目 venv 的 watch 启动器，再纳入它派生的 Python 子进程。
# 这样不会仅凭模块名终止其他项目的同名 orchestrator。
$venvPython = Join-Path $root '.venv\Scripts\python.exe'
$watchProcesses = @($processes | Where-Object { (Get-ServiceKind $_) -eq 'orchestrator-watch' })
$watchRoots = @($watchProcesses | Where-Object { [string]$_.ExecutablePath -ieq $venvPython })
if ($watchRoots.Count -gt 1) { throw '发现多个本项目 orchestrator 启动器，无法安全判断；已中止重启。' }
if ($watchRoots.Count -eq 1) {
    $ownedIds = [System.Collections.Generic.HashSet[int]]::new()
    [void]$ownedIds.Add([int]$watchRoots[0].ProcessId)
    $added = $true
    while ($added) {
        $added = $false
        foreach ($processInfo in $watchProcesses) {
            if (-not $ownedIds.Contains([int]$processInfo.ProcessId) -and
                $ownedIds.Contains([int]$processInfo.ParentProcessId)) {
                [void]$ownedIds.Add([int]$processInfo.ProcessId)
                $added = $true
            }
        }
    }
    foreach ($processInfo in $watchProcesses | Where-Object { $ownedIds.Contains([int]$_.ProcessId) }) {
        $targets[[int]$processInfo.ProcessId] = 'orchestrator-watch'
    }
} elseif ($watchProcesses.Count -eq 1) {
    # Legacy direct interpreter launch has no venv shim; only accept an unambiguous match.
    $targets[[int]$watchProcesses[0].ProcessId] = 'orchestrator-watch'
} elseif ($watchProcesses.Count -gt 1) {
    throw '发现多个无法归属到本项目 venv 的 orchestrator 进程；已中止重启。'
}

if ($WhatIf) {
    if ($targets.Count -eq 0) { Write-Host '未发现需要停止的本项目服务进程。' }
    foreach ($target in $targets.GetEnumerator()) { Write-Host "将停止 $($target.Value) (PID $($target.Key))" }
    Write-Host 'WhatIf 模式：未停止进程，也未启动服务。'
    exit 0
}

$stopOrder = @('orchestrator-watch', 'm3-8001', 'model-8008')
foreach ($kind in $stopOrder) {
    $kindTargets = @($targets.GetEnumerator() | Where-Object { $_.Value -eq $kind })
    # Stop interpreter children before their venv launchers.
    $targetPids = @($kindTargets | ForEach-Object { [int]$_.Key })
    $kindTargets = @($kindTargets | Sort-Object {
        $currentPid = [int]$_.Key
        $processInfo = $processes | Where-Object { $_.ProcessId -eq $currentPid } | Select-Object -First 1
        if ($processInfo -and ($targetPids -contains [int]$processInfo.ParentProcessId)) { 0 } else { 1 }
    })
    foreach ($target in $kindTargets) {
        Write-Host "停止 $kind (PID $($target.Key)) ..."
        Stop-Process -Id ([int]$target.Key) -ErrorAction Stop
    }
}

foreach ($port in @(8001, 8008)) {
    $deadline = (Get-Date).AddSeconds(12)
    while ((Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 300
    }
    if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) {
        throw "端口 $port 尚未释放；停止在此处，不启动重复服务。"
    }
}

foreach ($pidFile in $pidFiles.Values) {
    if (Test-Path -LiteralPath $pidFile) { Remove-Item -LiteralPath $pidFile -Force }
}

Write-Host '旧服务已停止，正在按统一启动配置重新启动模型、M3 和编排器...'
& (Join-Path $PSScriptRoot 'start_all.ps1')
Write-Host '全系统重启流程完成。M3: http://127.0.0.1:8001；本地模型端口：8008。'
