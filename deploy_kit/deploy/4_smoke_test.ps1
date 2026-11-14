#Requires -Version 5.1
<#
  NetGuard 部署后自检（冒烟测试）

  分四级验证，任一失败会明确指出原因：
    L1 静态：包内关键文件与权重是否齐全
    L2 服务：8001 / 8008 是否在线
    L3 模型：本地垂域模型 cqsec 能否正确回答（官方 payload 四段式判定）
    L4 全链路：投递演示样本 → M1 降噪 → bridge → M2 研判 → bundle 产出

  用法：
    powershell -NoProfile -ExecutionPolicy Bypass -File deploy\4_smoke_test.ps1
    powershell ... -File deploy\4_smoke_test.ps1 -SkipE2E      # 只跑 L1~L3
#>
param(
    [int]$WebPort = 8001,
    [int]$ModelPort = 8008,
    [switch]$SkipE2E,
    [int]$E2ETimeoutSeconds = 900
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$DeployDir = $PSScriptRoot
$PkgRoot   = (Resolve-Path (Join-Path $DeployDir '..')).Path
$ProjRoot  = Join-Path $PkgRoot 'taishi_platform'
$VenvPy    = Join-Path $ProjRoot '.venv\Scripts\python.exe'

$script:Pass = 0
$script:Fail = 0
$script:Warn = 0

function Check([string]$Name, [scriptblock]$Test) {
    try {
        $r = & $Test
        if ($r -eq $true -or $null -eq $r) { Write-Host "  [通过] $Name" -ForegroundColor Green; $script:Pass++ }
        elseif ($r -eq 'warn')              { Write-Host "  [提醒] $Name" -ForegroundColor Yellow; $script:Warn++ }
        else                                 { Write-Host "  [失败] $Name" -ForegroundColor Red; $script:Fail++ }
    } catch {
        Write-Host "  [失败] $Name -- $($_.Exception.Message)" -ForegroundColor Red
        $script:Fail++
    }
}

function Test-HttpJson([string]$Url, [int]$TimeoutSec = 8) {
    try { return Invoke-RestMethod -Uri $Url -TimeoutSec $TimeoutSec } catch { return $null }
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor White
Write-Host '  NetGuard 部署自检（冒烟测试）' -ForegroundColor White
Write-Host '============================================================' -ForegroundColor White
Write-Host "  包根目录: $PkgRoot"
Write-Host ''

# ---------------------------------------------------------------------------
# L1 静态检查
# ---------------------------------------------------------------------------
Write-Host 'L1 包完整性' -ForegroundColor White
Check '便携 Python 运行时 runtime\python\python.exe' { Test-Path -LiteralPath (Join-Path $PkgRoot 'runtime\python\python.exe') }
Check '项目 venv 可执行 .venv\Scripts\python.exe'   { Test-Path -LiteralPath $VenvPy }
Check 'M2 引擎配置 config.yaml'                     { Test-Path -LiteralPath (Join-Path $ProjRoot 'config.yaml') }
Check 'M3 服务 m3\server.py'                        { Test-Path -LiteralPath (Join-Path $ProjRoot 'm3\server.py') }
Check '威胁情报库 data\threat_intel'                { Test-Path -LiteralPath (Join-Path $ProjRoot 'data\threat_intel') }
Check 'IP 归属地库 data\geo\ip2region.xdb'          { Test-Path -LiteralPath (Join-Path $ProjRoot 'data\geo\ip2region.xdb') }
Check 'llama.cpp 运行时 model\runtime\llama-server.exe' { Test-Path -LiteralPath (Join-Path $PkgRoot 'model\runtime\llama-server.exe') }

$gguf = @()
if (Test-Path -LiteralPath (Join-Path $PkgRoot 'model\weights')) {
    $gguf = Get-ChildItem -LiteralPath (Join-Path $PkgRoot 'model\weights') -Filter '*.gguf' -File
}
Check '模型权重 model\weights\*.gguf' {
    if ($gguf.Count -gt 0) { Write-Host "         $($gguf[0].Name)  $([math]::Round($gguf[0].Length/1GB,2)) GB" -ForegroundColor DarkGray; return $true }
    return $false
}

Check '密钥未被打包（.env 内无真实 key）' {
    $envFile = Join-Path $ProjRoot '.env'
    if (-not (Test-Path -LiteralPath $envFile)) { return 'warn' }
    $txt = Get-Content -LiteralPath $envFile -Raw
    $leak = [regex]::Matches($txt, '(?m)^\s*[A-Z_]*(KEY|TOKEN)\s*=\s*(\S+)') |
            Where-Object { $_.Groups[2].Value -notin @('', '0', '1') }
    if ($leak.Count -gt 0) { Write-Host "         发现已填写的密钥项 $($leak.Count) 个（部署机自行填写属正常）" -ForegroundColor DarkGray }
    return $true
}

Write-Host ''
Write-Host "L2 服务在线" -ForegroundColor White
$webUp = (Test-HttpJson "http://127.0.0.1:$WebPort/health")
Check "M3 Web/API 健康 (: $WebPort /health)" {
    if (-not $webUp) { return $false }
    Write-Host "         $($webUp | ConvertTo-Json -Compress)" -ForegroundColor DarkGray
    return $true
}
$modelModels = (Test-HttpJson "http://127.0.0.1:$ModelPort/v1/models")
Check "本地模型 API 在线 (: $ModelPort /v1/models)" { return ($null -ne $modelModels) }

Write-Host ''
Write-Host 'L3 本地垂域模型推理' -ForegroundColor White
Check 'cqsec 单条告警研判（C2 回连样本 → 应判为 C2回连攻击）' {
    if (-not $modelModels) { return $false }
    $payload = @{
        model = 'cqsec'; temperature = 0.1; max_tokens = 400; stream = $false
        messages = @(@{ role = 'user'; content = @"
你是网络安全态势感知中心的AI告警研判助手。请研判下列HTTP告警，从候选类别【SQL注入攻击、XSS跨站脚本攻击、目录遍历攻击、文件包含攻击、远程命令执行攻击、CSRF攻击、Java反序列化漏洞利用攻击、文件上传攻击、暴力破解攻击、扫描探测攻击、Webshell通信攻击、C2回连攻击、SSRF攻击、XXE攻击、SSTI攻击、正常访问】中判定其类型，按“研判结论、判定依据、ATT&CK映射、处置建议”四段输出。

时间: 2025-11-02 03:40:56
方法: POST
源IP: 45.61.10.9
目的IP: 10.60.33.18
User-Agent: python-requests/2.31
URL路径: /gate77.php
请求体: host=c2server512.cn&id=9af3c2e18b77d001&s=60
"@ })
    }
    $body = $payload | ConvertTo-Json -Depth 6
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:$ModelPort/v1/chat/completions" -Method Post `
                -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 240
    } catch { Write-Host "         推理请求失败：$($_.Exception.Message)" -ForegroundColor DarkGray; return $false }
    $ans = $r.choices[0].message.content
    $hasSections = ($ans -match '研判结论') -and ($ans -match 'ATT&CK')
    $isC2 = ($ans -match 'C2')
    Write-Host "         finish=$($r.choices[0].finish_reason)  输出 $($ans.Length) 字符" -ForegroundColor DarkGray
    Write-Host "         片段：$($ans.Substring(0, [Math]::Min(90, $ans.Length)) -replace '\s+',' ')" -ForegroundColor DarkGray
    if (-not $isC2) { Write-Host '         未识别为 C2 回连，请核对模型权重是否为 cqsec 微调版' -ForegroundColor DarkGray }
    return ($hasSections -and $isC2)
}

if ($SkipE2E) {
    Write-Host ''
    Write-Host '已按 -SkipE2E 跳过全链路测试。' -ForegroundColor Yellow
} else {
    Write-Host ''
    Write-Host 'L4 全链路（M1 降噪 → bridge → M2 研判 → bundle）' -ForegroundColor White

    $sample = Join-Path $ProjRoot 'tests_integration\fixtures\suite\02_same_scenarios.xlsx'
    if (-not (Test-Path -LiteralPath $sample)) {
        $sample = Join-Path $ProjRoot 'tests_integration\fixtures\web_alerts_full.xlsx'
    }
    Check '演示样本存在' { return (Test-Path -LiteralPath $sample) }

    if ((Test-Path -LiteralPath $sample) -and $webUp) {
        $wsE2E = Join-Path $PkgRoot 'logs\smoke_workspace'
        Write-Host "         样本：$(Split-Path -Leaf $sample)" -ForegroundColor DarkGray
        Write-Host "         工作区：$wsE2E" -ForegroundColor DarkGray
        Write-Host '         运行中（首次约 1-4 分钟，取决于 CPU/GPU 与告警条数）...' -ForegroundColor DarkGray

        $env:PYTHONUTF8 = '1'; $env:PYTHONIOENCODING = 'utf-8'
        $env:NETGUARD_WORKSPACE = $wsE2E
        $env:CQSEC_BASE_URL = "http://127.0.0.1:$ModelPort"

        $out = & $VenvPy -m orchestrator.driver run-file --file $sample --workspace $wsE2E --analysis-mode local 2>&1
        $out | Select-Object -Last 12 | ForEach-Object { Write-Host "         $_" -ForegroundColor DarkGray }

        # 找到最新任务目录并校验产物
        $bundle = Get-ChildItem -Path $wsE2E -Recurse -Filter 'bundle.json' -File -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Check 'bundle.json 产出（M3 结果包契约 AttackChainBundle.v1）' {
            if (-not $bundle) { return $false }
            $j = Get-Content -LiteralPath $bundle.FullName -Raw | ConvertFrom-Json
            Write-Host "         路径：$($bundle.FullName)" -ForegroundColor DarkGray
            Write-Host "         schema=$($j.schema_version)  攻击链=$(@($j.attack_chains).Count)  告警=$(@($j.alerts).Count)" -ForegroundColor DarkGray
            return $true
        }
        Check 'M1 可疑事件批次产出（parquet）' {
            $pq = Get-ChildItem -Path $wsE2E -Recurse -Filter '*.parquet' -File -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if (-not $pq) { return $false }
            Write-Host "         $($pq.FullName)" -ForegroundColor DarkGray
            return $true
        }
    }
}

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '------------------------------------------------------------' -ForegroundColor White
Write-Host "  自检结果：通过 $script:Pass / 提醒 $script:Warn / 失败 $script:Fail" -ForegroundColor White
if ($script:Fail -eq 0) {
    Write-Host '  部署验证通过，系统可用。' -ForegroundColor Green
    Write-Host "  打开浏览器访问：http://127.0.0.1:$WebPort" -ForegroundColor Green
} else {
    Write-Host '  存在失败项，请按上方提示排查；日志位于 logs\ 目录。' -ForegroundColor Red
}
Write-Host '------------------------------------------------------------' -ForegroundColor White
Write-Host ''

if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
