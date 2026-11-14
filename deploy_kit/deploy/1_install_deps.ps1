#Requires -Version 5.1
<#
  NetGuard 部署环境自检与依赖安装

  做三件事：
    1. 检查目标主机环境（Windows 版本、端口占用、磁盘空间、虚拟化/GPU）
    2. 用包内便携 Python 3.11 重建 taishi_platform\.venv
    3. 从包内 wheels\ 离线安装全部依赖（无需联网、无需预装 Python）

  典型用法（在包根目录执行）：
    powershell -NoProfile -ExecutionPolicy Bypass -File deploy\1_install_deps.ps1
#>
param(
    [switch]$CheckOnly,   # 只做环境检查，不安装
    [switch]$Force,       # 即使 venv 健康也强制重建
    [switch]$Quiet        # 供 2_start_all.ps1 调用时静默
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$DeployDir = $PSScriptRoot
$PkgRoot   = (Resolve-Path (Join-Path $DeployDir '..')).Path
$ProjRoot  = Join-Path $PkgRoot 'taishi_platform'
$PythonDir = Join-Path $PkgRoot 'runtime\python'
$PyExe     = Join-Path $PythonDir 'python.exe'
$VenvDir   = Join-Path $ProjRoot '.venv'
$VenvPy    = Join-Path $VenvDir 'Scripts\python.exe'
$Wheels    = Join-Path $DeployDir 'wheels'
$ReqFile   = Join-Path $DeployDir 'requirements.txt'

function Write-Step([string]$t) { if (-not $Quiet) { Write-Host "  $t" -ForegroundColor Cyan } }
function Write-Ok([string]$t)   { if (-not $Quiet) { Write-Host "  [OK]   $t" -ForegroundColor Green } }
function Write-Bad([string]$t)  { Write-Host "  [错误] $t" -ForegroundColor Red }
function Write-Warn2([string]$t){ Write-Host "  [提示] $t" -ForegroundColor Yellow }

Write-Host ''
Write-Host '============================================================' -ForegroundColor White
Write-Host '  NetGuard 部署环境自检' -ForegroundColor White
Write-Host '============================================================' -ForegroundColor White
Write-Host "  包根目录: $PkgRoot"
Write-Host "  目标项目: $ProjRoot"
Write-Host ''

# ============================================================================
# 一、环境检查
# ============================================================================
Write-Step '[检查 1] 操作系统'
$os = Get-CimInstance Win32_OperatingSystem
Write-Ok "$($os.Caption)  Build $($os.BuildNumber)  $($os.OSArchitecture)"
if ($os.BuildNumber -lt 10240) { Write-Warn2 '系统版本较低，仅 Windows 10/11 经过验证。' }

Write-Step '[检查 2] 便携 Python 运行时'
if (Test-Path -LiteralPath $PyExe) {
    $ver = & $PyExe -c "import sys; print(sys.version.split()[0])" 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Ok "包内便携 Python $ver（无需在目标主机安装 Python）" }
    else { Write-Bad "包内 Python 无法执行：$PyExe"; exit 1 }
} else {
    Write-Bad "缺失便携 Python：$PyExe"
    Write-Warn2 '请重新解压完整发行包（不要只复制 taishi_platform 子目录）。'
    exit 1
}

Write-Step '[检查 3] 离线依赖包 wheels\'
if (Test-Path -LiteralPath $Wheels) {
    $n = (Get-ChildItem -LiteralPath $Wheels -Filter '*.whl' -File | Measure-Object).Count
    if ($n -gt 0) { Write-Ok "$n 个 wheel 文件（可完全离线安装）" }
    else { Write-Bad 'wheels 目录为空'; exit 1 }
} else {
    Write-Bad "缺失 wheels 目录：$Wheels"; exit 1
}

Write-Step '[检查 4] 磁盘空间（当前盘）'
$drive = (Get-Item -LiteralPath $PkgRoot).PSDrive
$freeGB = [math]::Round($drive.Free / 1GB, 1)
if ($freeGB -ge 5) { Write-Ok "剩余 $freeGB GB（运行时还需写入 workspace 与模型缓存，建议 ≥5 GB）" }
else { Write-Warn2 "剩余仅 $freeGB GB，建议清理后重试（运行时建议 ≥5 GB）" }

Write-Step '[检查 5] 端口占用（8001 Web / 8008 模型）'
foreach ($p in @(8001, 8008)) {
    $busy = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
    if ($busy) { Write-Warn2 "端口 $p 已被占用（PID $($busy.OwningProcess -join ',')）；启动脚本会跳过或提示" }
    else { Write-Ok "端口 $p 空闲" }
}

Write-Step '[检查 6] GPU 加速能力（可选）'
$cudaDll = Join-Path $PkgRoot 'model\runtime\ggml-cuda.dll'
$smi = $null
try { $smi = & nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>$null } catch {}
if ($smi -and $LASTEXITCODE -eq 0) {
    Write-Ok "检测到 NVIDIA GPU：$smi"
    if (Test-Path -LiteralPath $cudaDll) { Write-Ok '包内已含 CUDA 运行库，模型将使用 GPU 推理' }
    else { Write-Warn2 '包内无 CUDA 运行库（CPU 版），模型将以 CPU 推理，速度较慢' }
} else {
    Write-Warn2 '未检测到 NVIDIA GPU；模型将以 CPU 推理（功能完整，速度较慢）'
}

if ($CheckOnly) {
    Write-Host ''
    Write-Host '  环境检查完成（未执行安装）。' -ForegroundColor Green
    Write-Host ''
    exit 0
}

# ============================================================================
# 二、重建虚拟环境
# ============================================================================
function Test-VenvHealthy {
    if (-not (Test-Path -LiteralPath $VenvPy)) { return $false }
    $probe = & $VenvPy -c "import fastapi, uvicorn, pyarrow, polars, httpx, openpyxl, reportlab, yaml, orjson; print('OK')" 2>&1
    return ($LASTEXITCODE -eq 0 -and ($probe -join '') -match 'OK')
}

Write-Step '[安装 1] 虚拟环境 taishi_platform\.venv'
if ((Test-VenvHealthy) -and -not $Force) {
    Write-Ok '现有 venv 健康，跳过重建（如需强制重建请加 -Force）'
} else {
    if ((Test-Path -LiteralPath $VenvDir) -and $Force) {
        Write-Step '按 -Force 移除旧 venv'
        Remove-Item -LiteralPath $VenvDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path -LiteralPath $VenvPy)) {
        Write-Step "用包内便携 Python 创建 venv..."
        & $PyExe -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) { Write-Bad 'venv 创建失败'; exit 1 }
        Write-Ok 'venv 创建完成'
    }
}
if (-not (Test-Path -LiteralPath $VenvPy)) { Write-Bad "venv 缺少 python.exe：$VenvPy"; exit 1 }

# pyvenv.cfg 路径修正（整包换目录后必需）
$cfg = Join-Path $VenvDir 'pyvenv.cfg'
if (Test-Path -LiteralPath $cfg) {
    $need = $true
    $cur = Get-Content -LiteralPath $cfg -Raw
    if ($cur -match [regex]::Escape($PythonDir)) { $need = $false }
    if ($need) {
        $out = Get-Content -LiteralPath $cfg | ForEach-Object {
            if ($_ -match '^\s*home\s*=') { "home = $PythonDir" }
            elseif ($_ -match '^\s*executable\s*=') { "executable = $(Join-Path $PythonDir 'python.exe')" }
            else { $_ }
        }
        Set-Content -LiteralPath $cfg -Value $out -Encoding ASCII
        Write-Ok 'pyvenv.cfg 路径已对齐当前包位置'
    }
}

# ============================================================================
# 三、离线安装依赖
# ============================================================================
Write-Step '[安装 2] 离线安装依赖'
if (Test-VenvHealthy) {
    Write-Ok '依赖已就绪，跳过'
} else {
    if (-not (Test-Path -LiteralPath $ReqFile)) { Write-Bad "缺失 $ReqFile"; exit 1 }
    Write-Step "pip install --no-index --find-links wheels（离线，约 1-2 分钟）"
    & $VenvPy -m pip install --no-index --find-links $Wheels --upgrade pip --quiet 2>&1 |
        Where-Object { $_ -notmatch '^\s*$' } | ForEach-Object { if (-not $Quiet) { Write-Host "    $_" -ForegroundColor DarkGray } }
    & $VenvPy -m pip install --no-index --find-links $Wheels -r $ReqFile 2>&1 |
        Where-Object { $_ -notmatch 'already satisfied' } |
        ForEach-Object { if (-not $Quiet) { Write-Host "    $_" -ForegroundColor DarkGray } }
    if ($LASTEXITCODE -ne 0) { Write-Bad '依赖安装失败；请检查 wheels 目录完整性'; exit 1 }
}

if (-not (Test-VenvHealthy)) { Write-Bad '依赖校验未通过，请查看上方 pip 输出。'; exit 1 }
Write-Ok '全部依赖校验通过'

# ============================================================================
# 四、项目数据自检
# ============================================================================
Write-Step '[安装 3] 运行数据自检'
$checks = @(
    @{ p = (Join-Path $ProjRoot 'config.yaml');                                  n = 'M2 引擎配置 config.yaml' },
    @{ p = (Join-Path $ProjRoot 'data\threat_intel');                            n = '威胁情报库 data\threat_intel' },
    @{ p = (Join-Path $ProjRoot 'data\geo\ip2region.xdb');                       n = 'IP 归属地库 ip2region.xdb' },
    @{ p = (Join-Path $ProjRoot 'm3\knowledge\attack_intro.json');               n = 'M3 攻击知识库' },
    @{ p = (Join-Path $PkgRoot  'model\runtime\llama-server.exe');               n = 'llama.cpp 推理运行时' }
)
foreach ($c in $checks) {
    if (Test-Path -LiteralPath $c.p) { Write-Ok $c.n } else { Write-Warn2 "缺少 $($c.n)（$($c.p)）" }
}
$ggufs = @()
if (Test-Path -LiteralPath (Join-Path $PkgRoot 'model\weights')) {
    $ggufs = Get-ChildItem -LiteralPath (Join-Path $PkgRoot 'model\weights') -Filter '*.gguf' -File
}
if ($ggufs.Count -gt 0) {
    foreach ($g in $ggufs) { Write-Ok "模型权重 $($g.Name)（$([math]::Round($g.Length/1GB,2)) GB）" }
} else {
    Write-Warn2 '缺少模型权重 model\weights\*.gguf —— 平台仍可运行，但本地垂域模型能力不可用'
}

Write-Host ''
Write-Host '------------------------------------------------------------' -ForegroundColor White
Write-Host '  环境就绪。下一步：' -ForegroundColor Green
Write-Host '    1) 如需云端大模型：编辑 secrets\.env 填入 API Key' -ForegroundColor White
Write-Host '    2) 一键启动：deploy\2_start_all.ps1' -ForegroundColor White
Write-Host '    3) 部署自检：deploy\4_smoke_test.ps1' -ForegroundColor White
Write-Host '------------------------------------------------------------' -ForegroundColor White
Write-Host ''
exit 0
