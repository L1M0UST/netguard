param(
    [switch]$RequireRunningServices
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$checks = [System.Collections.Generic.List[object]]::new()

function Add-Check([string]$Name, [bool]$Passed, [string]$Detail) {
    $checks.Add([pscustomobject]@{ name = $Name; passed = $Passed; detail = $Detail })
}

function Test-Port([int]$Port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try { $client.Connect('127.0.0.1', $Port); return $true }
    catch { return $false }
    finally { $client.Dispose() }
}

$python = Join-Path $root '.venv\Scripts\python.exe'
$fixture = Join-Path $root 'tests_integration\fixtures\suite\01_main_10k.csv'
$contestData = Join-Path $root 'tests_integration\fixtures\web_alerts_full.xlsx'
$runner = Join-Path $root 'scripts\competition_acceptance.py'
$startScript = Join-Path $root 'scripts\start_all.bat'

Add-Check 'project-root' ((Test-Path (Join-Path $root 'm1\run.py')) -and (Test-Path (Join-Path $root 'm3\server.py'))) $root
Add-Check 'python-venv' (Test-Path $python) $(if (Test-Path $python) { '项目 .venv 可用' } else { '缺少 .venv；参照 docs/赛前验证与复现说明.md 安装依赖' })
Add-Check 'acceptance-runner' (Test-Path $runner) $runner
Add-Check 'synthetic-fixture' (Test-Path $fixture) $fixture
Add-Check 'labeled-workbook' (Test-Path $contestData) $contestData
Add-Check 'unified-startup' (Test-Path $startScript) $startScript

$envFile = Join-Path $root '.env'
$hasEnv = Test-Path $envFile
Add-Check 'secret-config' $true $(if ($hasEnv) { '.env 存在；不读取或回显密钥值' } elseif (Test-Path (Join-Path $root '.env.example')) { '无本机 .env；本地模式可运行，云端模式需按模板配置' } else { '密钥文件缺失；本地模式仍可运行，云端模式需自行配置安全环境变量' })

if ($RequireRunningServices) {
    $api = Test-Port 8001
    Add-Check 'm3-8001' $api $(if ($api) { '127.0.0.1:8001 正在监听' } else { '未监听；运行 scripts/start_all.bat' })
    $model = Test-Port 8008
    Add-Check 'local-model-8008' $model $(if ($model) { '127.0.0.1:8008 正在监听' } else { '未监听；规则确定性降级仍可用，但本地模型链路未就绪' })
}

$checks | Format-Table -AutoSize
$failed = @($checks | Where-Object { -not $_.passed })
if ($failed.Count -gt 0) {
    Write-Error ("赛前检查失败：{0} 项" -f $failed.Count)
    exit 1
}
Write-Host '赛前静态检查通过。该检查不代替上传演示和全链路验收。' -ForegroundColor Green
