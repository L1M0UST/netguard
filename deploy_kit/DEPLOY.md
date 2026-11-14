# NetGuard 部署环境配置说明

> 网络安全态势智能感知平台（赛题2）· 最小可运行发行包
> 适用版本：taishi_platform 整合版（M1 降噪 + M2 研判 + M3 前端交互层）

本文档说明如何把本系统部署到**另一台主机**并跑通全链路。
按「最小可运行」原则组织：目标主机**无需预装 Python、无需联网、无需任何 API Key**，
把发行包整个复制过去即可运行。

---

## 一、系统构成与部署视图

```
┌─────────────────────────────────────────────────────────────────────┐
│                          目标主机（Windows 10/11 x64）                │
│                                                                     │
│   浏览器  ──►  M3 BFF  (m3/server.py)  :8001   前端页面 + 16 个 API   │
│                    │                                                │
│                    │ 轮询 STATUS / 读取 bundle.json                  │
│                    ▼                                                │
│              分析编排器 (orchestrator/driver.py watch)               │
│                    │ M1 → bridge → M2 → bundle 顺序调度               │
│                    ▼                                                │
│   文件输入 ──► M1 降噪 ──► bridge 契约转换 ──► M2 研判 ──► 结果包       │
│                    │                            ▲                   │
│                    └──► 本地垂域模型 cqsec :8008 ─┘                   │
│                         (llama.cpp + Qwen3-4B QLoRA v3.2 GGUF)      │
└─────────────────────────────────────────────────────────────────────┘
```

三个进程、两个端口：

| 组件 | 端口 | 启动方式 | 是否必需 |
|---|---|---|---|
| M3 Web/API + 前端 | 8001 | `deploy\2_start_all.ps1` 自动拉起 | 必需 |
| 分析编排器 | — | 同上（后台常驻） | 必需 |
| 本地垂域模型 cqsec | 8008 | 同上（llama.cpp） | 可选但强烈建议 |

本地模型不可用时系统仍可运行（自动降级为纯规则 + 检索），
但会失去「大模型研判 / 问答 / 运营总结」能力。

---

## 二、目标主机环境要求

### 2.1 必需

| 项目 | 要求 | 说明 |
|---|---|---|
| 操作系统 | Windows 10 / 11 x64 | 启动脚本为 PowerShell；已针对 Windows PowerShell 5.1 适配 |
| 磁盘空间 | **≥ 12 GB** | 发行包本体约 4.4 GB（含 CUDA）或 3.3 GB（纯 CPU），运行期还需 workspace 与模型缓存 |
| 内存 | **≥ 8 GB**（建议 16 GB） | GGUF Q4_K_M 约 2.5 GB，llama.cpp 加载 + Python 管线峰值约 4–5 GB |
| 权限 | 普通用户即可 | 无需管理员；但需允许 PowerShell 执行脚本（见 §3.1） |
| 端口 | 8001、8008 空闲 | 被占用时启动脚本会提示（8001 可改，见 §6.3） |

### 2.2 可选（提升体验，非必需）

| 项目 | 收益 | 说明 |
|---|---|---|
| NVIDIA 显卡（显存 ≥ 6 GB） | 模型推理从 CPU 的 5–15 token/s 提升到 60+ token/s | 发行包自带 CUDA 运行库；无显卡时自动回退 CPU |
| Python 3.11 | 无（包内自带便携 Python） | 仅当你想用系统 Python 时才需要 |
| 外网 | 云端大模型增强、在线威胁情报 | 纯本地模式完全不需要外网 |

### 2.3 完全不需要

- ❌ 不需要预装 Python、pip、conda
- ❌ 不需要预装 CUDA Toolkit / cuDNN（运行库已随包）
- ❌ 不需要 Docker
- ❌ 不需要任何大模型 API Key
- ❌ 不需要 NVIDIA 显卡（CPU 也能跑完整功能）

---

## 三、部署步骤

### 步骤 0：复制发行包到目标主机

把整个发行包目录复制到目标主机任意位置（例如 `D:\NetGuard_Deploy`）。

> **必须整包复制**（推荐用 7-Zip / WinRAR 解压，或 `robocopy <源> <目标> /E`）。
> 不要只挑 `taishi_platform` 子目录 —— 便携 Python、模型权重、离线依赖都在同级目录。

### 步骤 1：环境自检

在发行包根目录打开 **PowerShell**，执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\1_install_deps.ps1 -CheckOnly
```

预期输出：逐项报告操作系统、便携 Python、离线依赖、磁盘空间、端口、GPU 情况。

### 步骤 2：（可选）填写 API Key

**纯本地模式可以完全跳过本步骤。** 需要云端增强时：

```powershell
Copy-Item secrets\.env.template secrets\.env
notepad secrets\.env
```

密钥只需改 `secrets\.env` 一个文件，详见 `secrets\README-密钥填写说明.md`。

`secrets\.env` 中保持 `DEEPSEEK_ENABLED=0` 即为纯本地模式（**推荐比赛现场使用**）：
不联网、不消耗额度、演示过程完全可控。

### 步骤 3：安装依赖（离线，约 1–2 分钟）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\1_install_deps.ps1
```

该脚本用**包内便携 Python** 重建 `taishi_platform\.venv`，并从 `deploy\wheels\`
离线安装全部依赖。若发行包已预建好 venv（默认会），此步骤会自动跳过安装，只做校验。

### 步骤 4：一键启动

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\2_start_all.ps1
```

脚本按顺序完成：

1. 载入 `secrets\.env` → `taishi_platform\.env`
2. 校验/修复/重建 Python 运行时
3. 初始化 `workspace\` 骨架与 `workspace\m1\config.json`（密钥字段留空）
4. 启动本地模型 cqsec（:8008），自动检测显卡决定 GPU / CPU
5. 启动 M3 Web/API（:8001），等待健康检查通过
6. 启动分析编排器（`orchestrator.driver watch`）

看到 `启动完成` 后，浏览器打开 **http://127.0.0.1:8001**。

> 本地模型首次加载 2.5 GB 权重需要 5–30 秒，脚本会等到健康检查通过再继续。
> 若模型未在 5 分钟内就绪，平台仍会启动并自动降级，日志见 `logs\model-8008.log`。

### 步骤 5：部署自检

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\4_smoke_test.ps1
```

分四级验证，全部通过即部署成功：

| 级别 | 验证内容 |
|---|---|
| L1 包完整性 | 便携 Python、venv、config.yaml、威胁情报库、GGUF 权重、密钥未泄漏 |
| L2 服务在线 | 8001 健康检查、8008 模型 API 在线 |
| L3 模型推理 | 用官方 C2 回连样本调用 cqsec，校验四段式输出与类型判定正确 |
| L4 全链路 | 投递演示样本 → M1 降噪 → bridge → M2 研判 → 产出 `bundle.json` |

### 步骤 6：使用系统

1. 浏览器打开 http://127.0.0.1:8001
2. 上传告警文件（支持 CSV / XLSX / JSON / JSONL / PCAP，演示样本在
   `taishi_platform\tests_integration\fixtures\`）
3. 前端创建任务 → 页面实时显示进度（SSE）
4. 查看攻击链、攻击者画像、风险报告、威胁情报查询、AI 问答

### 停止服务

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\3_stop_all.ps1
```

只停止本包启动的进程（优先 PID 文件，其次端口归属），不影响主机上其它服务。

---

## 四、发行包目录说明

```
NetGuard_Deploy\
├── README.md                       快速开始（一页速查）
├── DEPLOY.md                       本文件 —— 部署环境配置说明
├── MANIFEST.txt                    包清单与各部分体积
├── SHA256SUMS.txt                  关键文件校验和
│
├── taishi_platform\                ★ 项目主体
│   ├── .venv\                      预建虚拟环境（用包内便携 Python 创建）
│   ├── m1\                         成员A后端：告警接入 + 智能降噪（L1 规则 / L2 会话 / L3 语义）
│   ├── backend\module2_chain\      成员B后端：攻击关联 + 智能研判引擎
│   ├── m3\                         成员C前端 + BFF（16 个 API + SSE）
│   ├── bridge\                     M1→M2 契约转换 + 官方中文标签层 + IOC 导出
│   ├── bundle\                     M2 输出 → AttackChainBundle.v1 组装器
│   ├── orchestrator\               流水线编排器（watch / run-file）
│   ├── llm\                        cqsec 本地垂域模型客户端（五大能力）
│   ├── data\                       威胁情报库 / 资产清单 / IP 归属地库
│   ├── config.yaml                 M2 引擎配置（所有阈值集中在此）
│   ├── workspace\                  运行时工作区（首次启动自动建骨架）
│   ├── docs\                       技术文档、验收指南、证据材料
│   └── tests / tests_integration\  测试与演示样本
│
├── model\                          ★ 本地微调模型
│   ├── weights\                    qwen3-4b-cqsec-v32-Q4_K_M.gguf  (2.5 GB)
│   ├── runtime\                    llama.cpp（llama-server.exe + 依赖 DLL）
│   ├── lora-adapter-v3_2\          LoRA 微调适配器（模型溯源 / 可复现）
│   ├── finetune-data\              训练配置、评测报告、SFT 数据集
│   └── api-references\             cqsec API 对接文档与官方测试用例
│
├── runtime\python\                 ★ 便携 CPython 3.11（43 MB，目标主机免安装）
│
├── deploy\                         ★ 部署脚本
│   ├── 1_install_deps.ps1          环境自检 + 依赖安装
│   ├── 2_start_all.ps1             一键启动（路径自适应）
│   ├── 3_stop_all.ps1              一键停止
│   ├── 4_smoke_test.ps1            部署后自检
│   ├── requirements.txt            锁定的依赖版本（45 项）
│   └── wheels\                     离线 wheel（无需联网装依赖）
│
├── secrets\                        ★ 密钥目录（唯一需要手填的地方）
│   ├── .env.template               环境变量模板 → 复制为 .env 后填写
│   ├── m1_config.template.json     M1 运行配置模板（密钥已留空）
│   └── README-密钥填写说明.md
│
├── deliverables\                   ★ 交付材料占位（后续补充）
│   ├── 01_演示PPT\
│   ├── 02_技术文档\
│   ├── 03_演示视频\
│   └── 04_其他材料\
│
└── logs\                           运行日志（启动后生成）
```

---

## 五、模型说明

### 5.1 模型是什么

| 项目 | 内容 |
|---|---|
| 基座模型 | Qwen3-4B-Instruct-2507 |
| 微调方式 | QLoRA SFT（LLaMA-Factory），v3.2 为最终版 |
| 训练数据 | 赛题 HTTP 告警数据构建的指令集（`dataset\cqsec_judge` + `model\finetune-data\sft-dataset-v3_2`） |
| 交付格式 | GGUF **Q4_K_M** 量化，2.5 GB（`model\weights\qwen3-4b-cqsec-v32-Q4_K_M.gguf`） |
| 推理引擎 | llama.cpp `llama-server`（OpenAI Chat Completions 兼容） |
| 服务地址 | `http://127.0.0.1:8008/v1/chat/completions` |

### 5.2 五大能力与调用约束

| # | 能力 | 输入 | 系统内调用点 |
|---|---|---|---|
| 1 | 单条告警研判 | 一条告警的 7 字段 | M1 L3 级联第一档 |
| 2 | 事件研判报告 | 同一事件聚合的多条告警 | bundle 报告生成 |
| 3 | 攻击者画像 | 攻击者 IP + 行为摘要 | M3 画像接口 |
| 4 | 威胁情报问答 | 自然语言问题 | M3 `/api/v1/chat` |
| 5 | 运营总结 | 批次统计摘要 | 任务完成后自动生成 |

**调用约束（重要）**：模型按「指令 + 空行 + 数据」合并成**单条 `user` 消息**训练，
因此

- `messages` 数组**只放 1 条** `role:"user"` 消息
- **不要**使用 `system` 角色或多轮对话（未训练，输出质量不保证）
- `max_tokens` 建议 300–600（给少了会被截断，`finish_reason:"length"`）
- `temperature` 建议 0–0.3（研判类任务要稳定可复现）

完整调用示例与验收标准见 `model\api-references\`，或
`taishi_platform\docs\` 下的模型对接文档。

### 5.3 模型启动参数

`deploy\2_start_all.ps1` 实际使用的参数（可按需调整）：

```
llama-server.exe -m <权重路径> --host 127.0.0.1 --port 8008 \
                 -c 8192 -np 4 -fa on --threads <CPU核数/2> [-ngl 99]
```

| 参数 | 含义 | 调优建议 |
|---|---|---|
| `-c 8192` | 上下文长度 | 单条告警远够；显存紧张可降到 4096 |
| `-np 4` | 并发槽位 | 与 M1 的 `local_max_concurrency: 4` 对齐，调大不会提升实际并行 |
| `-ngl 99` | 全部层卸载到 GPU | 仅检测到 NVIDIA 显卡时附加；显存不足可减半（如 `-ngl 20`） |
| `--threads` | CPU 线程数 | 默认 CPU 核数一半；纯 CPU 部署时可调到物理核数 |

### 5.4 未随包提供的模型产物（如需可回开发机取）

| 文件 | 体积 | 为什么没打进来 |
|---|---|---|
| `qwen3-4b-cqsec-v32-f16.gguf` | 8.0 GB | 全精度权重，仅重新量化时用 |
| `Qwen3-4B-Instruct-2507` 基座 | 7.6 GB | 仅重新训练/合并时用 |
| 训练 venv + LLaMA-Factory | 5.6 GB | 仅训练需要 |
| LoRA `checkpoint-180` | ~380 MB | 中间检查点，最终适配器已在包内 |

---

## 六、配置项详解

### 6.1 环境变量（`secrets\.env`）

| 变量 | 默认值 | 作用 |
|---|---|---|
| `CQSEC_BASE_URL` | `http://127.0.0.1:8008` | 本地模型地址；换机器部署且模型在别处时改这里 |
| `CQSEC_MODEL` | `cqsec` | 模型名（服务端不校验，仅回显） |
| `CQSEC_TIMEOUT_SECONDS` | `120` | 单次推理超时；GPU 慢或 `max_tokens` 大时上调 |
| `CQSEC_OPS_SUMMARY` | `1` | 任务完成后是否生成中文运营总结（0=关） |
| `DEEPSEEK_ENABLED` | `0` | 云端总开关。**0 = 纯本地**，不联网 |
| `NETGUARD_WORKSPACE` | `./workspace` | 工作区根目录（启动脚本会注入绝对路径） |
| `NETGUARD_DATA_DIR` | `./m3/data` | M3 状态库目录（含 `state.sqlite3`） |
| `NETGUARD_LLM_PROTOCOL` | `cqsec` | `cqsec`=纯文本协议（本地模型）；`json`=结构化（云端） |
| `NETGUARD_LLM_ENABLED` | `1` | M3 问答开关 |
| `NETGUARD_RAW_TTL_HOURS` | `72` | 上传原始文件保留时长（过期自动清理） |
| `NETGUARD_ACTOR` | `local-user` | 审计日志中的操作者标识 |
| `NETGUARD_PDF_FONT` | `C:\Windows\Fonts\msyh.ttc` | 报告 PDF 中文字体；非 Windows 部署需改 |

### 6.2 引擎配置（`taishi_platform\config.yaml`）

M2 引擎的**全部业务阈值**都在这里，改完重启即生效。常用项：

| 配置 | 默认 | 说明 |
|---|---|---|
| `correlation.correlation_window_seconds` | 300 | 攻击关联时间窗 |
| `correlation.link_threshold` | 0.55 | 关联判定阈值（调高更保守） |
| `llm.provider` | `cloud_chain` | 云端链路；纯本地场景可改 `disabled` |
| `llm.max_candidates` | 60 | 每任务送 LLM 的候选上限（控制耗时与成本） |
| `llm.fail_open` | `true` | LLM 失败时降级到规则链（不要改 false） |
| `risk.severity_thresholds` | 85/70/45/20 | 严重等级五档分界 |
| `workspace.root` | `workspace` | 工作区根（相对项目根） |

### 6.3 改端口

```powershell
# 换 Web 端口为 9001、模型端口为 9008
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\2_start_all.ps1 -WebPort 9001 -ModelPort 9008
```

若改了模型端口，同步把 `secrets\.env` 的 `CQSEC_BASE_URL` 改成 `http://127.0.0.1:9008`。

---

## 七、运行与运维

### 7.1 日志位置

| 文件 | 内容 |
|---|---|
| `logs\model-8008.log` | 本地模型服务输出（加载进度、推理计时） |
| `logs\model-8008-error.log` | 模型启动失败原因（显存不足、权重损坏等） |
| `logs\m3-8001.log` | Web/API 访问日志 |
| `logs\m3-8001-error.log` | Web/API 异常堆栈 |
| `logs\orchestrator-console.log` | 流水线调度日志（M1→M2 各阶段） |
| `.run\*.pid` | 各服务进程号（停止脚本使用） |

### 7.2 常见问题

**Q1：`2_start_all.ps1` 报「禁止运行脚本」/ `无法加载文件`**

PowerShell 执行策略受限。两种解决方式：

```powershell
# 方式一：单次绕过（推荐，无需改系统设置）
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\2_start_all.ps1

# 方式二：为当前用户放开
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

**Q2：模型启动了但推理很慢（几十秒一条）**

未启用 GPU。检查：
1. `nvidia-smi` 是否可用
2. `model\runtime\ggml-cuda.dll` 是否存在
3. `logs\model-8008.log` 是否出现 `CUDA` 字样，或是否报显存不足

显存不足时模型会自动回退 CPU；可手工把启动参数 `-ngl 99` 改小（如 `-ngl 20`）。

**Q3：页面能打开，但创建任务后一直「处理中」**

按顺序检查：
1. 编排器是否在跑：`logs\orchestrator-console.log` 有无新日志
2. M1 是否报错：`logs\orchestrator-console-error.log`
3. 本地模型是否在线：浏览器访问 `http://127.0.0.1:8008/health`
4. 工作区是否有写入：`taishi_platform\workspace\incoming\`

模型离线不会导致任务卡死，M1 会跳过 L3 语义研判继续走规则链。

**Q4：端口 8001 / 8008 被占用**

```powershell
# 查看占用者
Get-NetTCPConnection -LocalPort 8001,8008 -State Listen | Select-Object LocalPort,OwningProcess

# 停掉本包自己的残留进程
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\3_stop_all.ps1

# 或换端口启动（见 §6.3）
```

**Q5：整包换了目录后 venv 起不来**

`taishi_platform\.venv\pyvenv.cfg` 里记录的是绝对路径。
`deploy\1_install_deps.ps1` 与 `2_start_all.ps1` 都会**自动检测并修正**该路径；
若仍失败，强制重建：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\1_install_deps.ps1 -Force
```

**Q6：中文显示为乱码 / 脚本解析失败**

启动脚本已写入 UTF-8 BOM 并设置控制台编码。若在旧版 CMD 中手工执行
PowerShell 内容，改用 `.ps1` 脚本入口，不要复制粘贴脚本正文。

**Q7：报告导出 PDF 中文变成方块**

`NETGUARD_PDF_FONT` 指向的微软雅黑缺失。在 `secrets\.env` 中改为目标机已有字体：

```
NETGUARD_PDF_FONT=C:\Windows\Fonts\simhei.ttf
NETGUARD_PDF_FONT_BOLD=C:\Windows\Fonts\simhei.ttf
```

**Q8：想清空演示数据重新来过**

页面右上角有「重置演示」按钮，或调用 `POST /api/v1/admin/reset`。
也可直接停止服务后删除 `taishi_platform\workspace\*` 与 `taishi_platform\m3\data\state.sqlite3`，
下次启动会自动重建。

### 7.3 性能参考基线

| 场景 | 参考值 |
|---|---|
| 模型冷启动（加载 2.5 GB GGUF） | GPU 约 5–15 秒 / CPU 约 20–60 秒 |
| 单条告警研判（cqsec，max_tokens=400） | GPU 约 2–4 秒 / CPU 约 15–40 秒 |
| 端到端全链路（10,200 行合成集） | 见 `taishi_platform\docs\evidence\` 下的验收证据 JSON |
| 服务自身启动（不含模型） | 约 5–10 秒 |

注：以上为开发机（RTX 4060 Laptop 8 GB / Windows 11）实测量级，
目标主机性能取决于 CPU 核数、磁盘类型（SSD 显著优于 HDD）与显卡。

---

## 八、安全与合规

### 8.1 密钥处理

- 发行包在构建时已做**密钥扫描**：开发机 `.env`、`workspace\m1\config.json`
  中出现过的真实 API Key **全部未进入发行包**
- 包内唯一的密钥入口是 `secrets\.env`（由使用者自行填写）
- 构建脚本 `scripts\build_deploy_package.ps1` 在打包末尾会扫描
  `sk-*` / `oc_sk_*` / `user_*` / `AIza*` 等密钥特征，**命中即中止打包**

### 8.2 数据边界

- 交付包内只含比赛授权样本与项目内生成的确定性夹具，不含真实个人信息
- 本地模型推理**全程不联网**；纯本地模式（`DEEPSEEK_ENABLED=0`）下
  系统不发起任何外部请求
- 上传的原始告警文件默认保留 72 小时后自动清理（`NETGUARD_RAW_TTL_HOURS`）
- PCAP 能力边界见 `taishi_platform\docs\数据来源与PCAP边界.md`

### 8.3 交付前检查清单

- [ ] 确认 `secrets\.env` 是否已填入真实 Key（若需交付他人，请先删除该文件）
- [ ] 确认 `taishi_platform\workspace\m1\config.json` 的 `api_key` 字段为空
- [ ] 确认 `taishi_platform\.env` 与 `secrets\.env` 一致或已删除
- [ ] 交付材料（PPT / 文档 / 录屏）中不含密钥、真实数据
- [ ] 运行 `deploy\4_smoke_test.ps1` 全项通过

---

## 九、已知限制

1. **运行平台**：启动脚本为 PowerShell，当前仅适配 Windows。项目 Python 代码
   本身跨平台，在 Linux 上需自行改写启动脚本并替换 PDF 字体。
2. **`pyproject.toml` 的 `tests_m1` 路径**：配置中引用了 `tests_m1` 目录，
   但该目录在整合过程中未落地。直接运行 `pytest` 会因路径不存在报错；
   部署使用不受影响，如需跑测试请改用
   `python -m pytest backend\module2_chain\tests tests_integration`。
3. **PCAP 处理**：当前为元数据级解析，不做完整载荷重组。
4. **云端模型指标**：验收证据中的性能数据来自本地 M1 + 确定性 M2 链路，
   未把云模型作为评分依赖；云端的准确率与成本需单独测试。
5. **历史文档中的预估耗时**：早于当前实测的证据不作为结论引用，
   以 `docs\evidence\` 下带文件哈希与环境的 JSON 为准。

---

## 十、从源码重建发行包

在开发机上（`taishi_platform` 根目录）：

```powershell
# 默认构建（含 CUDA）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_deploy_package.ps1

# 纯 CPU 版（体积 -1.1 GB）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_deploy_package.ps1 -NoCuda

# 指定输出目录
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_deploy_package.ps1 -OutDir D:\NetGuard_Deploy

# 只重建项目部分（迭代部署脚本时用）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_deploy_package.ps1 -SkipModel
```

构建脚本会：脱敏复制项目 → 收集模型与运行时 → 复制便携 Python →
生成离线 wheel → 预建 venv → **扫描密钥（命中即中止）** → 输出 `MANIFEST.txt`
与 `SHA256SUMS.txt`。

部署套件的源文件在 `taishi_platform\deploy_kit\`，修改后再重新构建即可。

---

## 十一、快速命令速查

```powershell
# 环境自检（不改动任何东西）
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\1_install_deps.ps1 -CheckOnly

# 安装/修复依赖（离线）
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\1_install_deps.ps1 -Force

# 启动
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\2_start_all.ps1

# 启动（不启本地模型，纯规则降级）
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\2_start_all.ps1 -NoModel

# 启动（换端口）
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\2_start_all.ps1 -WebPort 9001 -ModelPort 9008

# 停止
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\3_stop_all.ps1

# 部署自检
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\4_smoke_test.ps1

# 自检（跳过全链路，只验到模型推理）
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\4_smoke_test.ps1 -SkipE2E

# 手工跑一次全链路（不走前端）
cd taishi_platform
.venv\Scripts\python.exe -m orchestrator.driver run-file `
  --file tests_integration\fixtures\suite\02_same_scenarios.xlsx `
  --workspace ..\logs\manual_workspace --analysis-mode local

# 直接调本地模型（模型 API 自测）
curl.exe -s http://127.0.0.1:8008/v1/models
```
