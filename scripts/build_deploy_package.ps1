#Requires -Version 5.1
<#
  NetGuard 最小可运行发行包 — 构建脚本

  把「项目 + 本地微调模型 + 推理运行时 + 便携 Python + 离线依赖」组装成一个
  可以在任意 Windows 主机上直接运行的发行包。

  设计原则：
    · 最小可运行 —— 只收运行时真正需要的东西，训练态资产/测试工作区/日志一律不入包
    · 零密钥      —— 开发机上的真实 API Key 不进包，密钥统一放 secrets\ 由使用者填写
    · 路径自适应  —— 包内所有启动脚本不写死盘符，整包复制到任意目录均可运行
    · 完全离线    —— 自带便携 Python 与离线 wheel，目标主机无需装 Python、无需联网

  用法（在 taishi_platform 根目录）：
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_deploy_package.ps1
    powershell ... -File scripts\build_deploy_package.ps1 -OutDir D:\NetGuard_Deploy
    powershell ... -File scripts\build_deploy_package.ps1 -NoCuda          # 纯 CPU 版，省 1.1 GB
    powershell ... -File scripts\build_deploy_package.ps1 -SkipModel       # 只重建项目部分
    powershell ... -File scripts\build_deploy_package.ps1 -NoClean -SkipProject -SkipModel -SkipVenv   # 增量重跑校验/清单
#>
param(
    [string]$OutDir = 'E:\platform_taishi\NetGuard_Deploy',
    [switch]$NoCuda,            # 不带 CUDA 运行库（纯 CPU 推理，体积 -1.1 GB）
    [switch]$SkipModel,         # 跳过模型/权重复制（调试项目部分时用）
    [switch]$SkipLora,          # 不带 LoRA 适配器（-145 MB）
    [switch]$SkipVenv,          # 不预建 .venv（首次启动时再建）
    [switch]$SkipProject,       # 不重新复制项目（迭代部署脚本时用）
    [switch]$NoClean            # 不清空输出目录（配合 -Skip* 做增量重建）
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# ============================================================================
# 源路径（开发机）
# ============================================================================
$ProjRoot   = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ContestDirs = Get-ChildItem -Path 'E:\code' -Directory -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -like '*AI大模型创新应用大赛*' }
$ContestRoot = if ($ContestDirs) { $ContestDirs[0].FullName } else { $null }
$LlamaBin    = if ($ContestRoot) { Join-Path $ContestRoot 'tools\llamacpp\bin' } else { $null }
$CqworkRoot  = 'E:\cqwork'
$GgufDir     = Join-Path $CqworkRoot 'gguf'
$LoraDir     = Join-Path $CqworkRoot 'saves\qwen3-4b-cqsec\lora-sft-v3_2'
$BasePython  = 'D:\python3.11'
$Kit         = Join-Path $ProjRoot 'deploy_kit'

function Say([string]$t, [string]$c = 'Cyan') { Write-Host "  $t" -ForegroundColor $c }
function Head([string]$t) {
    Write-Host ''
    Write-Host "=== $t ===" -ForegroundColor White
}
function Die([string]$t) { Write-Host "  [错误] $t" -ForegroundColor Red; exit 1 }

function Invoke-Robocopy([string]$Src, [string]$Dst, [string[]]$Extra = @()) {
    if (-not (Test-Path -LiteralPath $Src)) { return }
    New-Item -ItemType Directory -Path $Dst -Force | Out-Null
    $base = @($Src, $Dst, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/R:1', '/W:1', '/MT:8')
    $null = robocopy @base @Extra
    if ($LASTEXITCODE -ge 8) { Die "robocopy 失败 ($LASTEXITCODE)：$Src -> $Dst" }
}

Write-Host ''
Write-Host '############################################################' -ForegroundColor White
Write-Host '  NetGuard 最小可运行发行包 — 构建' -ForegroundColor White
Write-Host '############################################################' -ForegroundColor White
Write-Host "  项目源      : $ProjRoot"
Write-Host "  输出目录    : $OutDir"
Write-Host "  模型项目根  : $(if ($ContestRoot) { $ContestRoot } else { '未找到（模型运行时会跳过）' })"
Write-Host "  GGUF 权重   : $GgufDir"
Write-Host "  便携 Python : $BasePython"
Write-Host "  CUDA 运行库 : $(if ($NoCuda) { '不包含（CPU 版）' } else { '包含' })"
Write-Host ''

# ============================================================================
# 预检
# ============================================================================
Head '预检'
$ggufQ4 = Join-Path $GgufDir 'qwen3-4b-cqsec-v32-Q4_K_M.gguf'
if (-not $SkipModel) {
    if (-not (Test-Path -LiteralPath $ggufQ4))     { Die "缺少 GGUF 权重：$ggufQ4" }
    if (-not $LlamaBin -or -not (Test-Path -LiteralPath (Join-Path $LlamaBin 'llama-server.exe'))) { Die '缺少 llama.cpp 运行时（tools\llamacpp\bin\llama-server.exe）' }
}
if (-not (Test-Path -LiteralPath $BasePython))     { Die "缺少便携 Python 源目录：$BasePython" }
if (-not (Test-Path -LiteralPath $Kit))            { Die "缺少部署套件源目录：$Kit" }

Say "GGUF    $([math]::Round((Get-Item $ggufQ4 -ErrorAction SilentlyContinue).Length/1GB,2)) GB" 'DarkGray'
Say "便携Py  $BasePython" 'DarkGray'
Say '预检通过' 'Green'

# ============================================================================
# 准备输出目录
# ============================================================================
Head '准备输出目录'
if (Test-Path -LiteralPath $OutDir) {
    if ($NoClean) {
        Say "输出目录已存在，按 -NoClean 保留现有内容（增量重建）：$OutDir" 'Yellow'
    } else {
        $sizeGB = [math]::Round(((Get-ChildItem -LiteralPath $OutDir -Recurse -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum / 1GB), 2)
        Say "输出目录已存在（$sizeGB GB），清空重建：$OutDir" 'Yellow'
        Remove-Item -LiteralPath $OutDir -Recurse -Force
    }
}
foreach ($d in @('', 'model\runtime', 'model\weights', 'model\finetune-data', 'model\api-references',
                 'runtime', 'deploy', 'secrets', 'logs', '.run',
                 'deliverables\01_演示PPT', 'deliverables\02_技术文档',
                 'deliverables\03_演示视频', 'deliverables\04_其他材料')) {
    New-Item -ItemType Directory -Path (Join-Path $OutDir $d) -Force | Out-Null
}
Say "已创建：$OutDir" 'Green'

# ============================================================================
# 1) 项目主体（脱敏复制）
# ============================================================================
if (-not $SkipProject) {
    Head '1/8 复制项目主体（脱敏）'

    # 不进入发行包的运行时/开发态目录
    $xd = @(
        (Join-Path $ProjRoot 'workspace'),        # 运行时数据 + M1 配置（含密钥）
        (Join-Path $ProjRoot 'workspace_test'),   # 验收测试产物（2.1 GB）
        (Join-Path $ProjRoot '.venv'),            # 开发机 venv（绑定 D:\python3.11）
        (Join-Path $ProjRoot 'logs'),
        (Join-Path $ProjRoot 'tmp'),
        (Join-Path $ProjRoot 'output'),           # 运行期导出的报告
        (Join-Path $ProjRoot '.pytest_cache'),
        (Join-Path $ProjRoot 'm3\data'),          # M3 状态库 state.sqlite3
        (Join-Path $ProjRoot 'docs\_ppt_render'),
        (Join-Path $ProjRoot 'docs\_render'),
        (Join-Path $ProjRoot 'deploy_kit')        # 单独复制到包根
    )
    $xf = @('.env', '.env.local', '*.pyc', '.tmp_task.json', 'M2)',
            'workspacebridgetest-bridge-001evidence.json')
    # 按目录名全局排除（这些目录散布在项目各处）
    $xdByName = @('__pycache__', '.git', 'node_modules', '.pytest_cache',
                  '.mypy_cache', '.ruff_cache', '.ipynb_checkpoints')

    Invoke-Robocopy $ProjRoot (Join-Path $OutDir 'taishi_platform') `
        (@('/XD') + $xd + $xdByName + @('/XF') + $xf)

    # 运行时要用的空目录骨架
    foreach ($d in @('workspace\incoming', 'workspace\m1', 'workspace\m2', 'workspace\m2_inbox',
                     'workspace\04_m2_inbox', 'workspace\05_m2_output', 'workspace\06_status',
                     'workspace\bridge', 'workspace\m3', 'workspace\mappings', 'workspace\orchestrator',
                     'm3\data')) {
        New-Item -ItemType Directory -Path (Join-Path $OutDir "taishi_platform\$d") -Force | Out-Null
    }
    $projSize = [math]::Round(((Get-ChildItem -LiteralPath (Join-Path $OutDir 'taishi_platform') -Recurse -File |
                 Measure-Object -Property Length -Sum).Sum / 1MB), 1)
    Say "项目已复制：$projSize MB" 'Green'
} else {
    Head '1/8 跳过项目复制（-SkipProject）'
}

# ============================================================================
# 2) 本地模型权重
# ============================================================================
if (-not $SkipModel) {
    Head '2/8 复制本地模型权重（GGUF Q4_K_M）'
    Copy-Item -LiteralPath $ggufQ4 -Destination (Join-Path $OutDir 'model\weights') -Force
    Say "qwen3-4b-cqsec-v32-Q4_K_M.gguf  $([math]::Round((Get-Item $ggufQ4).Length/1GB,2)) GB" 'Green'
    Say '（未包含 f16 全精度版 8 GB 与基座模型 7.6 GB — 仅训练态需要，推理不使用）' 'DarkGray'

    if (-not $SkipLora) {
        Head '2b/8 复制 LoRA 微调适配器（v3.2，模型溯源）'
        $loraOut = Join-Path $OutDir 'model\lora-adapter-v3_2'
        New-Item -ItemType Directory -Path $loraOut -Force | Out-Null
        foreach ($f in @('adapter_model.safetensors', 'adapter_config.json', 'chat_template.jinja',
                         'README.md', 'all_results.json', 'train_results.json', 'trainer_state.json',
                         'training_loss.png', 'tokenizer.json', 'tokenizer_config.json')) {
            $src = Join-Path $LoraDir $f
            if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $loraOut -Force }
        }
        Say '已包含 adapter_model.safetensors 等微调产物（不含 checkpoint-180 中间态）' 'Green'
    }

    Head '2c/8 复制训练配置 / 评测报告 / API 对接资料'
    $ftOut = Join-Path $OutDir 'model\finetune-data'
    New-Item -ItemType Directory -Path (Join-Path $ftOut 'train-configs') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $ftOut 'eval-reports') -Force | Out-Null
    Invoke-Robocopy (Join-Path $ContestRoot 'model\train')          (Join-Path $ftOut 'train-configs')
    Invoke-Robocopy (Join-Path $ContestRoot 'model\output\eval')    (Join-Path $ftOut 'eval-reports')
    Invoke-Robocopy (Join-Path $ProjRoot    'dataset\cqsec_judge')  (Join-Path $ftOut 'sft-dataset-v3_2')
    Invoke-Robocopy (Join-Path $ContestRoot 'model\api')            (Join-Path $OutDir 'model\api-references') @('/XD', (Join-Path $ContestRoot 'model\api\__pycache__'))
    Say '已包含：训练 yaml、评测报告、SFT 数据集、cqsec API 用例' 'Green'
} else {
    Head '2/8 跳过模型复制（-SkipModel）'
}

# ============================================================================
# 3) llama.cpp 推理运行时（最小依赖集）
# ============================================================================
if (-not $SkipModel) {
    Head '3/8 复制 llama.cpp 推理运行时'
    $rtOut = Join-Path $OutDir 'model\runtime'
    # 实测最小依赖集（CPU 推理）：以下文件即可让 llama-server 加载 GGUF 并推理
    $core = @('llama-server.exe', 'llama-server-impl.dll', 'llama.dll', 'llama-common.dll',
              'ggml.dll', 'ggml-base.dll', 'libomp.dll', 'llama-tokenize.exe', 'mtmd.dll')
    foreach ($f in $core) {
        $src = Join-Path $LlamaBin $f
        if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $rtOut -Force }
    }
    # CPU 指令集变体（llama.cpp 按当前 CPU 自动选择一个）
    Get-ChildItem -LiteralPath $LlamaBin -Filter 'ggml-cpu-*.dll' -File |
        Copy-Item -Destination $rtOut -Force
    Say 'CPU 推理依赖已就位（约 26 MB）' 'Green'

    if (-not $NoCuda) {
        # GPU 加速：ggml-cuda + cuBLAS/cuDART 运行库
        foreach ($f in @('ggml-cuda.dll', 'cublas64_12.dll', 'cublasLt64_12.dll', 'cudart64_12.dll')) {
            $src = Join-Path $LlamaBin $f
            if (Test-Path -LiteralPath $src) {
                Copy-Item -LiteralPath $src -Destination $rtOut -Force
                Say "  + $f  $([math]::Round((Get-Item $src).Length/1MB,0)) MB" 'DarkGray'
            }
        }
        Say 'CUDA 运行库已就位；无 NVIDIA 显卡时自动回退 CPU 推理' 'Green'
    } else {
        Say '已按要求跳过 CUDA（纯 CPU 版）' 'Yellow'
    }
    Say '（未包含 llama.zip / cudart.zip 原始压缩包 645 MB — 解压后内容已就位）' 'DarkGray'
} else {
    Head '3/8 跳过推理运行时（-SkipModel）'
}

# ============================================================================
# 4) 便携 Python
# ============================================================================
Head '4/8 复制便携 Python 3.11 运行时'
$pyOut = Join-Path $OutDir 'runtime\python'
Invoke-Robocopy $BasePython $pyOut @('/XD',
    (Join-Path $BasePython 'Doc'), (Join-Path $BasePython 'Tools'),
    (Join-Path $BasePython 'include'), (Join-Path $BasePython 'Scripts'),
    (Join-Path $BasePython 'Lib\site-packages'), (Join-Path $BasePython 'Lib\test'),
    (Join-Path $BasePython 'Lib\idlelib'), (Join-Path $BasePython 'Lib\turtledemo'),
    (Join-Path $BasePython 'Lib\__pycache__'))
# 保留 ensurepip：离线创建 venv 必需
$pySize = [math]::Round(((Get-ChildItem -LiteralPath $pyOut -Recurse -File |
           Measure-Object -Property Length -Sum).Sum / 1MB), 0)
$pyExe = Join-Path $pyOut 'python.exe'
if (-not (Test-Path -LiteralPath $pyExe)) { Die '便携 Python 复制不完整' }
$ver = & $pyExe -c "import sys, sqlite3; print(sys.version.split()[0])" 2>&1
if ($LASTEXITCODE -ne 0) { Die "便携 Python 自检失败：$ver" }
Say "便携 Python $ver 就绪（$pySize MB）" 'Green'

# ============================================================================
# 5) 部署套件（脚本 + 密钥模板 + 交付占位）
# ============================================================================
Head '5/8 安装部署套件'
Invoke-Robocopy $Kit $OutDir
foreach ($f in @('README.md', 'DEPLOY.md', '部署清单与体积说明.md')) {
    $src = Join-Path $Kit $f
    if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $OutDir -Force }
}
Say '部署脚本 / 密钥模板 / 交付占位目录已就位' 'Green'

# ============================================================================
# 6) 离线依赖 wheels + requirements.txt
# ============================================================================
Head '6/8 生成离线依赖 wheels'
$wheelsOut = Join-Path $OutDir 'deploy\wheels'
New-Item -ItemType Directory -Path $wheelsOut -Force | Out-Null

$srcVenvPy = Join-Path $ProjRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $srcVenvPy)) { Die "找不到开发机 venv：$srcVenvPy（生成依赖清单需要它）" }

# 冻结开发机上实测可用的依赖版本，保证发行环境与验证环境一致
$frozen = & $srcVenvPy -m pip freeze 2>$null | Where-Object { $_ -match '==' }
$reqOut = Join-Path $OutDir 'deploy\requirements.txt'
$frozen | Set-Content -LiteralPath $reqOut -Encoding ASCII
Say "已冻结 $($frozen.Count) 个依赖版本 → deploy\requirements.txt" 'Green'

Say '下载 wheel（需要外网，约 1-3 分钟）...'
$dl = & $srcVenvPy -m pip download --only-binary=:all: --dest $wheelsOut -r $reqOut 2>&1
if ($LASTEXITCODE -ne 0) {
    $dl | Select-Object -Last 12 | ForEach-Object { Say "  $_" 'DarkGray' }
    Say 'wheel 下载失败；可手动补：pip download --only-binary=:all: --dest deploy\wheels -r deploy\requirements.txt' 'Yellow'
} else {
    $whl = Get-ChildItem -LiteralPath $wheelsOut -Filter '*.whl' -File
    $whlMB = [math]::Round(($whl | Measure-Object -Property Length -Sum).Sum / 1MB, 0)
    Say "已下载 $($whl.Count) 个 wheel（$whlMB MB）→ deploy\wheels" 'Green'
}

# ============================================================================
# 7) 预建虚拟环境（用包内便携 Python，保证整包可移植）
# ============================================================================
if (-not $SkipVenv) {
    Head '7/8 预建虚拟环境（taishi_platform\.venv）'
    $venvDir = Join-Path $OutDir 'taishi_platform\.venv'
    if (Test-Path -LiteralPath $venvDir) { Remove-Item -LiteralPath $venvDir -Recurse -Force }
    & $pyExe -m venv $venvDir
    if ($LASTEXITCODE -ne 0) { Die 'venv 创建失败' }
    $venvPy = Join-Path $venvDir 'Scripts\python.exe'
    $whlCount = (Get-ChildItem -LiteralPath $wheelsOut -Filter '*.whl' -File -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($whlCount -gt 0) {
        Say '离线安装依赖...'
        & $venvPy -m pip install --no-index --find-links $wheelsOut -r $reqOut --quiet 2>&1 |
            Where-Object { $_ -match 'error|ERROR' } | ForEach-Object { Say "  $_" 'DarkGray' }
        $probe = & $venvPy -c "import fastapi, uvicorn, pyarrow, polars, httpx, openpyxl, reportlab, yaml, orjson; print('OK')" 2>&1
        if ($LASTEXITCODE -ne 0 -or ($probe -join '') -notmatch 'OK') {
            Say "依赖校验未通过，首次启动时会自动重建。详情：$probe" 'Yellow'
        } else {
            $venvMB = [math]::Round(((Get-ChildItem -LiteralPath $venvDir -Recurse -File |
                       Measure-Object -Property Length -Sum).Sum / 1MB), 0)
            Say "虚拟环境就绪（$venvMB MB），开箱即可启动" 'Green'
        }
    } else {
        Say 'wheel 不可用，venv 已建但未装依赖；首次启动会自动安装' 'Yellow'
    }
} else {
    Head '7/8 跳过 venv 预建（-SkipVenv）'
}

# ============================================================================
# 8) 脱敏校验 + 清单
# ============================================================================
Head '8/8 脱敏校验与清单'

# 8a) 确保包内不存在 .env（只留模板）
$badEnv = Get-ChildItem -LiteralPath $OutDir -Recurse -File -Filter '.env' -ErrorAction SilentlyContinue
foreach ($f in $badEnv) { Remove-Item -LiteralPath $f.FullName -Force; Say "已移除 .env：$($f.FullName)" 'Yellow' }

# 8b) 扫描已知密钥特征
Say '扫描密钥泄漏...'
$patterns = @(
    'sk-[A-Za-z0-9]{16,}',            # DeepSeek / OpenAI 风格（不含连字符，避免误匹配 SPDX 许可证标识）
    'oc_sk_[A-Za-z0-9_-]{12,}',       # OpenCode
    'user_[A-Za-z0-9]{40,}',          # 其它平台
    'AIza[A-Za-z0-9_-]{30,}'          # Google 风格
)
# 二进制/压缩容器不做文本扫描：无法匹配明文，且会产生噪声误报
$skipExt = @('.safetensors', '.gguf', '.dll', '.exe', '.zip', '.whl', '.png', '.jpg', '.jpeg',
             '.gif', '.pdf', '.sqlite3', '.parquet', '.db', '.pyc',
             '.docx', '.pptx', '.xlsx', '.doc', '.ppt', '.xls')
# 第三方代码不做扫描：venv 里是 pip 装的公开包、wheels 是同一个包、
# runtime\python 是原版 CPython 标准库，都不可能是本项目泄漏的密钥来源，
# 却大量含有 SPDX 许可证标识之类的高熵文本，扫它们只会产生误报。
$skipDirs = @(
    (Join-Path $OutDir 'taishi_platform\.venv'),
    (Join-Path $OutDir 'deploy\wheels'),
    (Join-Path $OutDir 'runtime\python')
)

# 单元测试用假密钥：这些是测试代码里断言「日志脱敏生效」用的合成值，不是真实凭据。
# 判据（任一命中即视为假密钥）：
#   1) 命中已知合成样本清单
#   2) 含有占位词（secret/example/dummy/fake/your/xxx/placeholder/sample/redact/value/test）
#   3) 出现 8 个以上连续递增字母（abcdefgh…）或同一字符重复 8 次以上
$dummyAllow = @('sk-abcdefghijklmnop', 'sk-abcdefghijklmnopqrstuvwxyz', 'sk-secret-value-123456')
$dummyWords = @('secret', 'example', 'dummy', 'fake', 'placeholder', 'sample',
                'redact', 'value', 'test', 'your', 'xxx', 'xxxx', 'changeme', 'todo')
function Test-DummyToken([string]$Tok) {
    $t = $Tok.ToLower()
    if ($dummyAllow -contains $t) { return $true }
    foreach ($w in $dummyWords) { if ($t.Contains($w)) { return $true } }
    if ($t -match 'abcdefghi|bcdefghij|cdefghijk|defghijkl|efghijklm|fghijklmn|ghijklmno|hijklmnop|ijklmnopq') { return $true }
    if ($t -match '(.)\1{7,}') { return $true }
    return $false
}

$hits  = @()   # 疑似真实密钥（致命）
$dummy = @()   # 已判定为测试用假密钥（提示）
$scanFiles = Get-ChildItem -LiteralPath $OutDir -Recurse -File -ErrorAction SilentlyContinue |
             Where-Object {
                 $file = $_
                 $file.Length -lt 20MB -and
                 $skipExt -notcontains $file.Extension.ToLower() -and
                 -not ($skipDirs | Where-Object { $file.FullName.StartsWith($_) })
             }
foreach ($f in $scanFiles) {
    try { $txt = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { continue }
    # 空文件时 Get-Content -Raw 返回 $null，正则前必须挡掉
    if ([string]::IsNullOrEmpty($txt)) { continue }
    $rel = $f.FullName.Substring($OutDir.Length).TrimStart('\')
    foreach ($p in $patterns) {
        foreach ($m in [regex]::Matches($txt, $p)) {
            if (Test-DummyToken $m.Value) { $dummy += "$rel  ->  $($m.Value)" }
            else                          { $hits  += "$rel  ->  $($m.Value)" }
        }
    }
}
if ($dummy.Count -gt 0) {
    Say "已识别 $($dummy.Count) 处测试用假密钥（非真实凭据，保留）：" 'DarkGray'
    $dummy | Select-Object -Unique | Select-Object -First 10 | ForEach-Object { Say "  $_" 'DarkGray' }
}
if ($hits.Count -gt 0) {
    Write-Host ''
    Say "发现 $($hits.Count) 处疑似真实密钥：" 'Red'
    $hits | Select-Object -Unique | Select-Object -First 30 | ForEach-Object { Say "  $_" 'Red' }
    Die '发行包中存在疑似密钥，已终止。请先脱敏后再打包（真实 Key 只能放在 secrets\ 模板之外）。'
} else {
    Say "已扫描 $($scanFiles.Count) 个文件，未发现真实密钥" 'Green'
}

# 8c) 清单
$totalBytes = (Get-ChildItem -LiteralPath $OutDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
$totalGB = [math]::Round($totalBytes / 1GB, 2)

function Get-DirSize([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return '—' }
    $b = (Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
          Measure-Object -Property Length -Sum).Sum
    if (-not $b) { return '0 MB' }
    if ($b -ge 1GB) { return "$([math]::Round($b/1GB,2)) GB" } else { return "$([math]::Round($b/1MB,1)) MB" }
}

$manifest = @()
$manifest += 'NetGuard 网络安全态势智能感知平台 — 最小可运行发行包'
$manifest += "生成时间：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$manifest += "包根目录：$OutDir"
$manifest += "包总体积：$totalGB GB"
$manifest += ''
$manifest += '【目录体积】'
foreach ($d in @('taishi_platform', 'taishi_platform\.venv', 'model', 'model\weights', 'model\runtime',
                 'model\lora-adapter-v3_2', 'model\finetune-data', 'model\api-references',
                 'runtime\python', 'deploy\wheels', 'secrets', 'deliverables')) {
    $manifest += ("  {0,-32} {1}" -f $d, (Get-DirSize (Join-Path $OutDir $d)))
}
$manifest += ''
$manifest += '【本包包含】'
$manifest += '  · taishi_platform/  项目源码（M1 降噪 / M2 研判 / M3 BFF / bridge / bundle / orchestrator）'
$manifest += '  · model/weights/    本地微调模型 cqsec（Qwen3-4B QLoRA v3.2 → GGUF Q4_K_M）'
$manifest += '  · model/runtime/    llama.cpp 推理运行时（含 CUDA 或纯 CPU）'
$manifest += '  · runtime/python/   便携 CPython 3.11（目标主机无需安装 Python）'
$manifest += '  · deploy/wheels/    离线依赖 wheel（无需联网即可装依赖）'
$manifest += '  · deploy/           一键安装 / 启停 / 自检脚本'
$manifest += '  · secrets/          密钥填写目录（模板，不含真实密钥）'
$manifest += '  · deliverables/     交付材料占位（PPT / 文档 / 视频）'
$manifest += ''
$manifest += '【本包不包含（按最小可运行原则排除）】'
$manifest += '  · 基座模型 Qwen3-4B-Instruct-2507（7.6 GB，仅训练需要）'
$manifest += '  · GGUF f16 全精度权重（8.0 GB，训练/转换中间产物）'
$manifest += '  · 训练 venv 与 LLaMA-Factory（5.6 GB）'
$manifest += '  · attack-stix-data 知识库（1.5 GB，运行时不引用）'
$manifest += '  · workspace_test 验收测试产物（2.1 GB）'
$manifest += '  · 运行期工作区数据、日志、缓存、state.sqlite3'
$manifest += '  · 任何真实 API Key'
$manifest | Set-Content -LiteralPath (Join-Path $OutDir 'MANIFEST.txt') -Encoding UTF8

# 关键文件校验和
$sumTargets = @('taishi_platform\config.yaml', 'taishi_platform\.env.example',
                'deploy\2_start_all.ps1', 'secrets\.env.template',
                'model\weights\qwen3-4b-cqsec-v32-Q4_K_M.gguf')
$sums = foreach ($t in $sumTargets) {
    $full = Join-Path $OutDir $t
    if (Test-Path -LiteralPath $full) {
        $h = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
        "$h  $t"
    }
}
$sums | Set-Content -LiteralPath (Join-Path $OutDir 'SHA256SUMS.txt') -Encoding ASCII

# ============================================================================
# 完成
# ============================================================================
Write-Host ''
Write-Host '############################################################' -ForegroundColor Green
Write-Host '  构建完成' -ForegroundColor Green
Write-Host "    发行包：$OutDir" -ForegroundColor White
Write-Host "    总体积：$totalGB GB" -ForegroundColor White
Write-Host '############################################################' -ForegroundColor Green
Write-Host ''
Write-Host '  下一步（在发行包根目录执行）：' -ForegroundColor White
Write-Host '    powershell -NoProfile -ExecutionPolicy Bypass -File deploy\1_install_deps.ps1 -CheckOnly' -ForegroundColor Cyan
Write-Host '    powershell -NoProfile -ExecutionPolicy Bypass -File deploy\2_start_all.ps1' -ForegroundColor Cyan
Write-Host '    powershell -NoProfile -ExecutionPolicy Bypass -File deploy\4_smoke_test.ps1' -ForegroundColor Cyan
Write-Host ''
