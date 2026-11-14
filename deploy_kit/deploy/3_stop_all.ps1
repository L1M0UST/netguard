#Requires -Version 5.1
<#
  NetGuard 一键停止

  停止顺序：分析编排器 → M3 Web/API(8001) → 本地模型(8008)
  只杀本包启动的进程（优先 PID 文件，其次按端口归属，最后按命令行特征），
  不会影响机器上其它无关的 python / 服务。
#>
param(
    [int]$WebPort = 8001,
    [int]$ModelPort = 8008
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$DeployDir = $PSScriptRoot
$PkgRoot   = (Resolve-Path (Join-Path $DeployDir '..')).Path
$StateDir  = Join-Path $PkgRoot '.run'

function Write-Step([string]$t) { Write-Host "  $t" -ForegroundColor Cyan }
function Write-Ok([string]$t)   { Write-Host "  [OK]   $t" -ForegroundColor Green }
function Write-Warn2([string]$t){ Write-Host "  [提示] $t" -ForegroundColor Yellow }

function Stop-ByPidFile([string]$Name, [string]$File) {
    if (-not (Test-Path -LiteralPath $File)) { return $false }
    $pidText = (Get-Content -LiteralPath $File -Raw).Trim()
    Remove-Item -LiteralPath $File -Force -ErrorAction SilentlyContinue
    if (-not $pidText) { return $false }
    $proc = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
    if ($proc) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Write-Ok "$Name 已停止 (PID $($proc.Id))"
        return $true
    }
    return $false
}

function Stop-ByPort([string]$Name, [int]$Port) {
    $owners = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
              Select-Object -ExpandProperty OwningProcess -Unique
    if (-not $owners) { return $false }
    foreach ($o in $owners) {
        Stop-Process -Id $o -Force -ErrorAction SilentlyContinue
        Write-Ok "$Name 已停止（端口 $Port 占用进程 PID $o）"
    }
    return $true
}

function Stop-ByCmdLine([string]$Name, [string]$Pattern) {
    $hit = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -match $Pattern }
    if (-not $hit) { return $false }
    foreach ($p in $hit) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        Write-Ok "$Name 已停止 (PID $($p.ProcessId))"
    }
    return $true
}

Write-Host ''
Write-Host '------------------------------------------------------------' -ForegroundColor White
Write-Host '  NetGuard 停止服务' -ForegroundColor White
Write-Host '------------------------------------------------------------' -ForegroundColor White

Write-Step '停止分析编排器'
if (-not (Stop-ByPidFile '分析编排器' (Join-Path $StateDir 'orchestrator.pid'))) {
    if (-not (Stop-ByCmdLine '分析编排器' 'orchestrator\.driver\s+watch')) { Write-Warn2 '分析编排器 未在运行' }
}

Write-Step "停止 M3 Web/API (:$WebPort)"
if (-not (Stop-ByPidFile 'M3 Web/API' (Join-Path $StateDir 'm3.pid'))) {
    if (-not (Stop-ByPort 'M3 Web/API' $WebPort)) { Write-Warn2 "端口 $WebPort 无监听进程" }
}

Write-Step "停止本地模型 (:$ModelPort)"
if (-not (Stop-ByPidFile '本地模型' (Join-Path $StateDir 'model.pid'))) {
    $llama = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match 'llama-server' }
    if ($llama) {
        foreach ($p in $llama) {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Ok "本地模型 已停止 (PID $($p.ProcessId))"
        }
    } elseif (-not (Stop-ByPort '本地模型' $ModelPort)) {
        Write-Warn2 "端口 $ModelPort 无监听进程"
    }
}

Start-Sleep -Seconds 2
Write-Host ''
Write-Step '结果确认'
foreach ($pair in @(@('M3 Web/API', $WebPort), @('本地模型', $ModelPort))) {
    $still = Get-NetTCPConnection -LocalPort $pair[1] -State Listen -ErrorAction SilentlyContinue
    if ($still) { Write-Warn2 "$($pair[0]) 端口 $($pair[1]) 仍在监听" }
    else        { Write-Ok "$($pair[0]) 端口 $($pair[1]) 已释放" }
}
Write-Host ''
Write-Host '  停止完成。' -ForegroundColor Green
Write-Host ''
