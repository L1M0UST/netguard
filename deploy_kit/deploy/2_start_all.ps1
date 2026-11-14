#Requires -Version 5.1
<#
  NetGuard 一键启动（路径自适应版）

  与开发机上的 start_all.ps1 不同，本脚本不写死任何绝对路径：
  所有目录都以「包根目录」（本文件所在 deploy\ 的上一级）为基准推导，
  因此整个包可以整体复制到任意盘符/任意目录后直接运行。

  启动顺序：本地模型(8008) → M3 Web/API(8001) → 分析编排器
#>
param(
    [int]$WebPort = 8001,
    [int]$ModelPort = 8008,
    [switch]$NoModel,          # 只启动平台，不启动本地模型（平台会自动降级）
    [switch]$NoOrchestrator,   # 不启动分析编排器
    [switch]$Force             # 忽略已运行检测，直接重启
)

$ErrorActionPreference = 'Stop'
$OutputEncoding = [System.Text.Encoding]::UTF8
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# ============================================================================
# 目录解析（全部相对包根）
# ============================================================================
$DeployDir = $PSScriptRoot
$PkgRoot   = (Resolve-Path (Join-Path $DeployDir '..')).Path
$ProjRoot  = Join-Path $PkgRoot 'taishi_platform'
$PythonDir = Join-Path $PkgRoot 'runtime\python'
$VenvPy    = Join-Path $ProjRoot '.venv\Scripts\python.exe'
$ModelRt   = Join-Path $PkgRoot 'model\runtime'
$ModelExe  = Join-Path $ModelRt 'llama-server.exe'
$WeightDir = Join-Path $PkgRoot 'model\weights'
$Logs      = Join-Path $PkgRoot 'logs'
$StateDir  = Join-Path $PkgRoot '.run'

New-Item -ItemType Directory -Path $Logs     -Force | Out-Null
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

function Write-Step([string]$Text) { Write-Host "  $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "  [OK]   $Text" -ForegroundColor Green }
function Write-Warn2([string]$Text){ Write-Host "  [警告] $Text" -ForegroundColor Yellow }

function Test-Port([int]$Port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try { $client.Connect('127.0.0.1', $Port); return $true }
    catch { return $false }
    finally { $client.Dispose() }
}

function Test-Http([string]$Url, [int]$TimeoutSec = 5) {
    try {
        $r = Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSec -UseBasicParsing
        return ($r.StatusCode -eq 200)
    } catch { return $false }
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor White
Write-Host '  NetGuard 网络安全态势智能感知平台 - 启动' -ForegroundColor White
Write-Host '============================================================' -ForegroundColor White
Write-Host "  包根目录: $PkgRoot"
Write-Host ''

if (-not (Test-Path -LiteralPath $ProjRoot)) {
    throw "未找到项目目录：$ProjRoot。请确认包结构完整（deploy\ 与 taishi_platform\ 同级）。"
}

# ============================================================================
# 步骤 0：密钥配置 .env
# ============================================================================
Write-Step '[0/4] 检查密钥配置'
$ProjEnv      = Join-Path $ProjRoot '.env'
$SecretEnv    = Join-Path $PkgRoot 'secrets\.env'
$SecretTpl    = Join-Path $PkgRoot 'secrets\.env.template'

if (Test-Path -LiteralPath $ProjEnv) {
    Write-Ok '已存在 taishi_platform\.env（沿用，不覆盖）'
} elseif (Test-Path -LiteralPath $SecretEnv) {
    Copy-Item -LiteralPath $SecretEnv -Destination $ProjEnv -Force
    Write-Ok '已从 secrets\.env 载入密钥配置'
} elseif (Test-Path -LiteralPath $SecretTpl) {
    Copy-Item -LiteralPath $SecretTpl -Destination $ProjEnv -Force
    Write-Warn2 'secrets\.env 不存在，已用模板生成空配置：'
    Write-Warn2 '  → 系统将以「纯本地模式」运行（本地规则 + 本地模型），云端大模型不参与。'
    Write-Warn2 '  → 需要云端增强时，请编辑 secrets\.env 填入 key 后重新启动。'
} else {
    Write-Warn2 '未找到任何 .env 模板；将以「纯本地模式」运行。'
}

# ============================================================================
# 步骤 1：Python 运行时自检 / 自动修复
# ============================================================================
Write-Step '[1/4] 检查 Python 运行时'

function Test-VenvHealthy([string]$Py) {
    if (-not (Test-Path -LiteralPath $Py)) { return $false }
    $probe = & $Py -c "import fastapi, uvicorn, pyarrow, polars, httpx; print('OK')" 2>&1
    return ($LASTEXITCODE -eq 0 -and ($probe -join '') -match 'OK')
}

# 1a) 便携 Python 的路径修正：整包换目录后 pyvenv.cfg 里的 home 会失效
function Repair-Venv {
    $cfg = Join-Path $ProjRoot '.venv\pyvenv.cfg'
    if (-not (Test-Path -LiteralPath $cfg)) { return $false }
    if (-not (Test-Path -LiteralPath (Join-Path $PythonDir 'python.exe'))) { return $false }
    $lines = Get-Content -LiteralPath $cfg
    $out = foreach ($line in $lines) {
        if ($line -match '^\s*home\s*=') { "home = $PythonDir" }
        elseif ($line -match '^\s*executable\s*=') { "executable = $(Join-Path $PythonDir 'python.exe')" }
        else { $line }
    }
    # Windows PowerShell 5.1 写 UTF-8 无 BOM 即可，pyvenv.cfg 是 ASCII 内容
    Set-Content -LiteralPath $cfg -Value $out -Encoding ASCII
    return $true
}

$py = $VenvPy
if (Test-VenvHealthy $py) {
    Write-Ok "项目 venv 可用：$py"
} else {
    Write-Warn2 '项目 venv 不可用，尝试用包内便携 Python 修正路径...'
    if (Repair-Venv) {
        if (Test-VenvHealthy $py) { Write-Ok 'venv 路径已修正，运行时可用' }
        else { $py = $null }
    } else { $py = $null }
}

if (-not $py) {
    Write-Warn2 'venv 无法修复，将用包内便携 Python 离线重建（约 1-2 分钟）...'
    $installer = Join-Path $DeployDir '1_install_deps.ps1'
    if (-not (Test-Path -LiteralPath $installer)) { throw "缺少 $installer，无法重建运行时。" }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer -Quiet
    if ($LASTEXITCODE -ne 0) { throw '依赖重建失败，请查看上方输出或手动运行 deploy\1_install_deps.ps1。' }
    if (-not (Test-VenvHealthy $VenvPy)) { throw '依赖重建后 venv 仍不可用，请手动运行 deploy\1_install_deps.ps1 排查。' }
    $py = $VenvPy
    Write-Ok '运行时重建完成'
}

# ============================================================================
# 步骤 2：工作区与 M1 配置准备
# ============================================================================
Write-Step '[2/4] 准备工作区'

$WsRoot = Join-Path $ProjRoot 'workspace'
foreach ($d in @('incoming', 'm1', 'm2', 'm2_inbox', '04_m2_inbox', '05_m2_output', '06_status',
                 'bridge', 'm3', 'mappings', 'orchestrator')) {
    New-Item -ItemType Directory -Path (Join-Path $WsRoot $d) -Force | Out-Null
}

# M1 运行配置：从模板初始化（密钥一律留空，由 .env / 本地模型提供能力）
$M1Cfg     = Join-Path $WsRoot 'm1\config.json'
$M1Tpl     = Join-Path $PkgRoot 'secrets\m1_config.template.json'
if (-not (Test-Path -LiteralPath $M1Cfg) -and (Test-Path -LiteralPath $M1Tpl)) {
    Copy-Item -LiteralPath $M1Tpl -Destination $M1Cfg -Force
    Write-Ok '已从模板初始化 workspace\m1\config.json（不含任何密钥）'
} else {
    Write-Ok 'workspace\m1\config.json 已存在，沿用'
}

# M3 状态目录（首次启动会自动建库）
New-Item -ItemType Directory -Path (Join-Path $ProjRoot 'm3\data') -Force | Out-Null

# ============================================================================
# 步骤 3：本地模型（llama.cpp + GGUF）
# ============================================================================
Write-Step '[3/4] 本地垂域模型 cqsec (:8008)'

if ($NoModel) {
    Write-Warn2 '按参数跳过本地模型；平台将以规则+检索降级运行。'
} elseif (Test-Port $ModelPort) {
    Write-Ok "端口 $ModelPort 已有服务在运行，跳过启动"
} elseif (-not (Test-Path -LiteralPath $ModelExe)) {
    Write-Warn2 "未找到模型运行时 $ModelExe，跳过本地模型。"
} else {
    $weights = @()
    if (Test-Path -LiteralPath $WeightDir) {
        $weights = Get-ChildItem -LiteralPath $WeightDir -Filter '*.gguf' -File |
                   Sort-Object { if ($_.Name -match 'Q4_K_M') { 0 } elseif ($_.Name -match 'Q5') { 1 } else { 2 } }
    }
    if ($weights.Count -eq 0) {
        Write-Warn2 "未在 $WeightDir 找到 .gguf 权重，跳过本地模型。"
    } else {
        $gguf = $weights[0].FullName
        $hasCuda = Test-Path -LiteralPath (Join-Path $ModelRt 'ggml-cuda.dll')
        $hasGpu  = $false
        if ($hasCuda) {
            $null = & nvidia-smi --query-gpu=name --format=csv,noheader 2>$null
            $hasGpu = ($LASTEXITCODE -eq 0)
        }

        $threads = [Math]::Max(4, [int]([Environment]::ProcessorCount / 2))
        $args = @('-m', $gguf, '--host', '127.0.0.1', '--port', "$ModelPort", '-c', '8192', '-np', '4', '-fa', 'on', '--threads', "$threads")
        if ($hasGpu) { $args += @('-ngl', '99') }

        $modelLog = Join-Path $Logs 'model-8008.log'
        $modelErr = Join-Path $Logs 'model-8008-error.log'
        $proc = Start-Process -FilePath $ModelExe -ArgumentList $args -WorkingDirectory $ModelRt `
                              -WindowStyle Hidden -RedirectStandardOutput $modelLog -RedirectStandardError $modelErr -PassThru
        [System.IO.File]::WriteAllText((Join-Path $StateDir 'model.pid'), [string]$proc.Id)

        if ($hasGpu) { Write-Ok "本地模型启动中（GPU 加速，RTX 可用）权重：$($weights[0].Name)" }
        else         { Write-Ok "本地模型启动中（CPU 推理）权重：$($weights[0].Name)" }

        # GGUF 约 2.5GB，加载需要时间；给 5 分钟
        $deadline = (Get-Date).AddMinutes(5)
        $ready = $false
        while ((Get-Date) -lt $deadline) {
            if (Test-Http "http://127.0.0.1:$ModelPort/health" 3) { $ready = $true; break }
            if ($proc.HasExited) { break }
            Start-Sleep -Milliseconds 1500
        }
        if ($ready) { Write-Ok '本地模型就绪（健康检查通过）' }
        else {
            Write-Warn2 "本地模型未在 5 分钟内就绪，平台仍可启动（自动降级）。日志：$modelLog"
            if (Test-Path $modelErr) { Get-Content $modelErr -Tail 8 | ForEach-Object { Write-Warn2 "  $_" } }
        }
    }
}

# ============================================================================
# 步骤 4：M3 Web/API + 分析编排器
# ============================================================================
Write-Step "[4/4] M3 Web/API (:$WebPort) 与分析编排器"

$env:NETGUARD_WORKSPACE  = $WsRoot
$env:NETGUARD_DATA_DIR   = Join-Path $ProjRoot 'm3\data'
$env:NETGUARD_LLM_ENABLED = '1'
$env:NETGUARD_LLM_PROTOCOL = 'cqsec'
$env:CQSEC_BASE_URL      = "http://127.0.0.1:$ModelPort"
$env:PYTHONUTF8          = '1'
$env:PYTHONIOENCODING    = 'utf-8'

if ((Test-Port $WebPort) -and -not $Force) {
    Write-Ok "端口 $WebPort 已有服务在运行，跳过启动"
} else {
    if ((Test-Port $WebPort) -and $Force) {
        Write-Warn2 "端口 $WebPort 被占用，先停止旧进程..."
        Get-NetTCPConnection -LocalPort $WebPort -State Listen -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique |
            ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 2
    }
    $m3Out = Join-Path $Logs 'm3-8001.log'
    $m3Err = Join-Path $Logs 'm3-8001-error.log'
    $m3 = Start-Process -FilePath $py -ArgumentList @('-m', 'uvicorn', 'server:app', '--host', '127.0.0.1', '--port', "$WebPort") `
                        -WorkingDirectory (Join-Path $ProjRoot 'm3') -WindowStyle Hidden `
                        -RedirectStandardOutput $m3Out -RedirectStandardError $m3Err -PassThru
    [System.IO.File]::WriteAllText((Join-Path $StateDir 'm3.pid'), [string]$m3.Id)

    $deadline = (Get-Date).AddSeconds(40)
    $up = $false
    while ((Get-Date) -lt $deadline) {
        if (Test-Http "http://127.0.0.1:$WebPort/health" 3) { $up = $true; break }
        if ($m3.HasExited) { break }
        Start-Sleep -Milliseconds 800
    }
    if ($up) { Write-Ok "M3 就绪：http://127.0.0.1:$WebPort" }
    else {
        Write-Warn2 "M3 未能在 40 秒内就绪。错误日志：$m3Err"
        if (Test-Path $m3Err) { Get-Content $m3Err -Tail 15 | ForEach-Object { Write-Warn2 "  $_" } }
        throw 'M3 启动失败，已终止后续步骤。'
    }
}

if ($NoOrchestrator) {
    Write-Warn2 '按参数跳过分析编排器；投递的任务不会被处理。'
} else {
    $existing = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -match 'orchestrator\.driver\s+watch' }
    if ($existing -and -not $Force) {
        Write-Ok '分析编排器已在运行，跳过启动'
    } else {
        $orchOut = Join-Path $Logs 'orchestrator-console.log'
        $orchErr = Join-Path $Logs 'orchestrator-console-error.log'
        $orch = Start-Process -FilePath $py -ArgumentList @('-m', 'orchestrator.driver', 'watch') `
                              -WorkingDirectory $ProjRoot -WindowStyle Hidden `
                              -RedirectStandardOutput $orchOut -RedirectStandardError $orchErr -PassThru
        [System.IO.File]::WriteAllText((Join-Path $StateDir 'orchestrator.pid'), [string]$orch.Id)
        Start-Sleep -Seconds 2
        if ($orch.HasExited) {
            Write-Warn2 "分析编排器启动后立即退出，错误日志：$orchErr"
            if (Test-Path $orchErr) { Get-Content $orchErr -Tail 10 | ForEach-Object { Write-Warn2 "  $_" } }
        } else {
            Write-Ok '分析编排器已启动（监听 workspace\incoming）'
        }
    }
}

# ============================================================================
# 完成
# ============================================================================
Write-Host ''
Write-Host '------------------------------------------------------------' -ForegroundColor White
Write-Host '  启动完成' -ForegroundColor Green
Write-Host "    Web 界面 / API : http://127.0.0.1:$WebPort" -ForegroundColor White
Write-Host "    本地垂域模型    : http://127.0.0.1:$ModelPort/v1  (cqsec)" -ForegroundColor White
Write-Host "    日志目录        : $Logs" -ForegroundColor White
Write-Host '    停止服务        : deploy\3_stop_all.ps1' -ForegroundColor White
Write-Host '    部署自检        : deploy\4_smoke_test.ps1' -ForegroundColor White
Write-Host '------------------------------------------------------------' -ForegroundColor White
Write-Host ''
