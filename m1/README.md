# M1：数据接入与网络攻击初筛

本文对应规则 `m1-rules-1.3`、字段映射 `m1-schema-map-1.2`、L3 提示词 `m1-l3-judge-1.2`、M2 交付契约 `2.0`。

M1 核心是本地批处理程序，负责多格式读取、字段标准化、无意义记录过滤、去重、白名单、IOC 匹配、会话聚合、轻量打分和第一轮 LLM 语义判断。可启动 HTTP 适配服务供 M3 或内置文件选择页提交任务，不必手写 Manifest；也可使用原 intake 清单入口。完整 ATT&CK 映射、跨资产攻击链、攻击者画像和最终报告留给 M2 等后续模块，不执行自动封禁。

## 1. 安装与运行

推荐交互入口：安装下述依赖后，双击根目录 `start_m1_api.bat`，打开 `http://127.0.0.1:8765/`。刷新共享文件列表，选择已上传文件，点击开始分析。文件须先放入 shared-workspace/incoming；页面不是上传服务。任务在后台串行处理，当前窗口须保持开启。模型、IOC、Parquet 等继续读取服务器 m1/config.json；无需新建 excel-001.json。

命令行支持无 Manifest 分析，三种入口选一种：

```powershell
python -m m1.run --workspace .\shared-workspace --select
python -m m1.run --workspace .\shared-workspace --file web_alerts.xlsx
python -m m1.run --workspace .\shared-workspace --manifest .\shared-workspace\manifests\excel-001.json
```

API 服务启动：`python -m m1.api --workspace .\shared-workspace`。M3 对接详见 [接口文档](../docs/M1_M3_API.md)。文件走共享目录，HTTP 只传控制参数和元数据，不接受任意磁盘路径或密钥配置。API/CLI 均按实际配置调用 LLM，提交前确认配置。

使用 Python 3.10+，在项目根目录执行命令，不要进入 `m1` 子目录启动。安装依赖与运行程序必须使用同一个 Python 环境。

在文件资源管理器中打开项目根目录（包含 `m1`、`shared-workspace` 和 `update_ioc.bat` 的文件夹），在地址栏输入 `cmd` 并回车，即可在该目录打开命令提示符。也可在此目录打开 PowerShell。

本文中的文件位置均采用项目相对路径，不依赖个人用户名、盘符或固定安装目录。命令中的 `--workspace` 指定数据工作目录，Manifest 内的相对输入路径则以该工作目录为基准。

安装 XLSX 和 Parquet 依赖并运行现有任务：

```powershell
python -m pip install openpyxl pyarrow
python -c "import sys, openpyxl, pyarrow; print(sys.executable); print(pyarrow.__version__)"
python -m m1.run --workspace .\shared-workspace --manifest .\shared-workspace\manifests\excel-001.json
```

仅当读取旧版 XLS 时额外安装 `python -m pip install pandas xlrd`。XLSX/Parquet 不要求 pandas。

结束时命令打印本次结果目录 `shared-workspace/m1/ready/batch-excel-001/<run_id>/`。每次运行生成新 `run_id`，不覆盖旧输出；修改配置、代码、IOC 后须重新执行任务。

## 2. 项目文件与工作目录

| 文件或目录 | 作用 |
| --- | --- |
| `m1/run.py` | 命令入口、格式解析、映射、清洗、L1、聚合评分、LLM/微步客户端与批次编排 |
| `m1/l2.py` | 滑动窗口扫描检测、路径归一化、身份/攻击类别及时间分组辅助逻辑 |
| `m1/quality.py` | 复核模式分组、可疑/未入选双向抽样、人工标签评估 |
| `m1/similarity.py` | 载荷摘要、SimHash 分桶检索和 Jaccard 复核分组校验；不删除事件 |
| `m1/intake.py` | 检查 incoming 中稳定的新文件，自动生成唯一编号 Manifest |
| `m1/api.py` | M3 HTTP 接口、持久任务队列、状态查询、输入快照 |
| `m1/shared_files.py` | 共享 incoming 文件列表、文件版本标识与路径约束 |
| `m1/select_file.html` | 本机文件选择、任务提交与轮询页面 |
| `start_m1_api.bat` | 双击启动本机 API 服务 |
| `watch_incoming.bat` | 双击启动任务清单监听，关闭窗口后停止 |
| `m1/local_ioc.py` | 公开 IOC 下载、SQLite 快照发布及离线索引匹配 |
| `m1/storage.py` | 分批写入 Parquet/JSONL，定义原生 List/Struct 类型 |
| `m1/handoff.py` | 文件哈希、发布校验、M2 可疑会话读取函数 |
| `m1/SuspiciousEventBatch.md` | M1 → M2 交付契约 |
| `m1/__init__.py` | Python 包标记 |
| `update_ioc.bat` | Windows 双击更新 IOC，每次启动更新一次 |
| `tests/` | 回归测试、真实 Excel 离线检查、合成数据性能检查 |

```text
shared-workspace/
  incoming/                         原始文件
  manifests/                        任务清单
  mappings/schema-*.json             可复用字段映射缓存
  m1/
    config.json                     实际配置，可含 API 密钥
    api/tasks.sqlite3               API 任务状态与幂等记录
    api/inputs/<task_id>/            API 输入快照，保留用于审计
    api/service.lock                 API 单实例锁
    local_ioc/                      ioc.sqlite3、update_status.json
    threatbook_cache/                微步查询缓存
    running/<task_id>-<run_id>.status.json
    failed/<task_id>-<run_id>.status.json
    staging/<run_id>/                暂存结果，M2 不读取
    ready/<batch_id>/<run_id>/       校验后发布的结果
```

## 3. 输入与 Manifest

| 格式 | 要求与读取方式 |
| --- | --- |
| CSV | UTF-8/UTF-8 BOM，首行为表头，逐行读取 |
| JSONL / NDJSON | UTF-8，每行一个对象 |
| JSON | 对象数组、单对象或包含 `records` 数组的对象；整文件解析 |
| XLSX | openpyxl 只读模式，遍历工作表，首行为表头、跳过空行；读取公式缓存值，不计算公式 |
| XLS | pandas/xlrd 读取，建议转为 XLSX |
| PCAP / PCAPNG | 简化 Ethernet IPv4 元数据解析，不是完整抓包分析器 |

Parquet 当前是输出格式，不是输入格式。抓包解析不保存完整应用载荷，不重组 TCP、不解密 HTTPS，也不完整支持 IPv6、VLAN、多接口或 PCAPNG 时间精度选项。

现有 `shared-workspace/manifests/excel-001.json`：

```json
{
  "schema_version": "1.0",
  "task_id": "excel-001",
  "batch_id": "batch-excel-001",
  "input_files": ["incoming/web_alerts.xlsx"],
  "options": {"session_window_seconds": 300}
}
```

使用 Manifest 时，input_files 相对路径以 --workspace 为基准，只处理清单列出的文件。使用 API、--file 或 --select 时直接选择 incoming 中一个文件，不需要清单；原 intake 仍作为可选兼容入口。

### 自动创建清单

双击根目录 `watch_incoming.bat` 并保持窗口打开，再将文件放入 `shared-workspace/incoming/`；或在根目录运行：

```powershell
python -m m1.intake --workspace .\shared-workspace --watch
```

默认每 3 秒检查一次，同一文件连续两次大小/修改时间不变且非空可读时，创建清单。移除 `--watch` 可只检查两轮后退出，`--interval` 支持 1～60 秒。Excel 用 excel 前缀，CSV 用 csv 等，从 001 起找未占用编号。你的 web_alerts.xlsx 已被 excel-001.json 引用，因此不会重复创建；新 Excel 将使用下一个未占用编号。文件名可不同于任务名。

仅检查 incoming 顶层支持扩展名的文件，跳过临时文件、空文件、隐藏名和 Excel 的 `~$` 文件。不覆盖旧清单，不自动处理数据或调用模型。同名文件替换后仍复用原清单，重新运行该任务即可处理新版数据。按 Ctrl+C 正常停止；异常断电留下 `manifests/.intake.lock` 时，确认旧进程已停止后再删除该锁文件。

大小稳定只是启发式判断，不保证暂停中的上传已完成。上传服务应先保存为 `.part` 等临时后缀，上传关闭文件后再重命名为 `.xlsx`；这也适用于大文件。当前没有网页上传服务，网页后端可按相同方式将文件交付到 incoming。扩展名不代表内容合法，实际解析错误由 M1 报告。

`task_id` 必填，`batch_id` 省略时为 `batch-<task_id>`，名称不能含目录分隔符。`options.session_window_seconds` 覆盖会话空闲窗口，`options.profile_sample_size` 覆盖样例数量，其余参数仍读取配置文件。

每个文件只使用一套冻结映射；不同工作表表头不一致时，建议拆成独立文件。解析器产生的 `_sheet_name` 当前不会作为标准字段保留到明细；输出行号是解析后事件序号，不保证等于 Excel 物理行号。请保留原始文件供审计。

## 4. 数据处理流程

### 4.1 字段识别与标准化

读取表头及前 N 条样例，默认 200，配置限制为 100～500，不足时使用现有记录。代码根据别名、类型和 IP/时间/端口/协议特征推断字段。

优先复用兼容 Mapping Plan；无缓存时先规则推断，剩余未识别字段才发送字段名、类型摘要和少量样例给映射模型。模型调用失败保留规则映射，结果必须符合标准字段与置信度门槛。映射冻结后，全部记录由程序转换，不逐条调用 AI。

方案缓存到 `mappings/schema-*.json`，并归档到本次输出 `mapping_plans/`。缓存依据格式、字段名及映射版本定位，加载时检查类型兼容性；同名但业务语义不同的文件仍须核对。

标准化包括 IP 合法性、端口范围、协议大写、时间转带时区字符串、事件 ID 和内容指纹。无时区时间按运行机器时区解释；无效时间置空并标记，无效 IP 清空，不一定删除整条记录。

### 4.2 清洗、去重和白名单

依次过滤空记录、缺少有效网络身份且没有安全内容的记录，再做内容指纹去重和来源白名单过滤。

指纹包含标准内容字段但不含时间，默认与 60 秒固定时间桶共同去重；同内容跨桶仍保留，缺失有效时间时不跨事件推断重复。被过滤的数据不写入 event_details，通过原文件和状态计数追溯。

`whitelist_ips` 匹配来源单 IP，`trusted_networks` 匹配来源 CIDR；目标是可信服务器不会使外部攻击请求跳过检测。

### 4.3 L1：单事件规则与 IOC

检测 SQL 注入、XSS、目录穿越、命令注入、扫描器、Java 反序列化、文件包含、可疑上传及 CSRF 参数。字段做有限轮解码且存在检测长度限制；命中是启发式信号，不证明攻击成功。

IOC 来自手工集合、SQLite 库及可选微步查询。`ioc_matches` 保存类型、值、字段和来源，SQLite 来源还保存下载时间、缓存到期时间。

通过过滤的已解析请求体、日志消息、User-Agent 等分批写入 `event_details.parquet`，随后从内存事件移除完整载荷，保留轻量字段和每类最多 512 字符的语义片段。完整明细不等于保留原文件全部列或抓包全部字节。

### 4.4 L2：行为、会话和风险

先对全部保留事件做行为检测，再聚合和筛选可疑会话，避免低分单事件提前被排除。

| 功能 | 当前实现 |
| --- | --- |
| 扫描检测 | 同源、目标、协议、目的端口和域名在 60 秒滑动窗口内至少 5 个归一化路径，且至少 2 个敏感路径，产生 `multi_path_scan` |
| 路径模板 | 移除 query，数字/UUID 路径段替换为占位符，保留大小写；不是通用机器学习聚类 |
| 共享出口扫描 | 还要求源端口相同；缺少源端口时不跨事件推断 |
| 基础会话 | 按源/目的 IP、源/目的端口、协议五元组合并；空闲超过 300 秒或持续达到 3600 秒时拆分 |
| 身份/时间缺失 | 不能安全关联的记录独立保留 |
| 会话频率分 | 只统计命中规则的成员数，3 条起加 10 分，10 条起加 20 分 |
| 来源活跃度 | 300 秒内同源会话至少 10 个且当前会话有证据时加 10 分；已配置共享出口加 2 分 |
| 资产重要性 | 有规则/IOC/行为证据才加 0～20 分；优先资产 ID，再按事件资产名/目标 IP 查权重 |
| 可疑筛选 | 有规则命中，或者风险分达到 `suspicious_min_score`（默认 45） |

基础分取成员最大分，再叠加权重，上限 100；75 起高危，45 起中危，其余低危。正常访问不因次数多或资产重要而单独加成攻击。分数是初筛优先级，不是概率。

`activity_groups` 结合多路径、资产、服务、域名和攻击类别生成相似活动候选，默认跨度 1800 秒。`attack_campaigns` 按资产/服务/域名/攻击类别生成活动候选，默认跨度 3600 秒；扫描标签来自前置行为证据，不凭一天路径多就判扫描。

两类关联采用首事件锚定的有界跨度，不按整点/午夜机械切分；超过跨度仍另起一组。共享出口不跨基础会话合并。关联不删除基础会话，同一会话可出现在多个路径分组，分组计数不能直接相加作为全局总量。完整跨资产关联由 M2 完成。

### 4.5 L3：有限候选语义研判

从中/高风险会话按分数并兼顾规则类别选候选，预算为：

```text
min(floor(原始事件数 × l3_max_ratio), floor(原始事件数 × 0.01))
```

`l3_max_ratio` 必须为 0～0.01 的有限数。当前配置 0.001，即 0.1%，11,000 条输入最多 11 个候选；取整为 0 时不调用。比例限制候选会话数，重试可增加 HTTP 请求数。

每个候选发送摘要和有界证据，受控并发调用。当前并发 3，客户端允许 1～16；瞬时错误默认重试 1 次（可配置 0～2）。连续候选失败达到阈值后停止提交新任务，但仍收集在途请求。

模型返回 verdict/confidence/summary/reasoning/recommended_action，合法结果单独保存。它不覆盖已有规则、IOC、评分，也不会因返回 benign 自动删除会话；block 只是建议，不执行封禁。

## 5. 配置方法

实际配置是 `shared-workspace/m1/config.json`，采用 UTF-8 标准 JSON，不支持注释或末尾逗号。以下片段须合并进现有配置，不要为改一项覆盖整文件。未提供配置时，加载器输出默认 JSONL；当前工作区已明确启用 Parquet。

### 5.1 处理和输出

| 字段 | 推荐值与含义 |
| --- | --- |
| `schema_profile_sample_size` | 200，范围自动限制 100～500 |
| `dedup_window_seconds` | 60，固定去重时间桶 |
| `session_window_seconds` | 300，相邻空闲窗口 |
| `max_session_duration_seconds` | 3600，最大会话时长 |
| `source_activity_window_seconds` | 300，来源活跃度窗口 |
| `scan_window_seconds` | 60，扫描滑动窗口 |
| `scan_min_unique_paths` | 5，至少为 2 |
| `scan_min_sensitive_paths` | 2，至少为 1；须与上一门槛同时满足 |
| `activity_window_seconds` | 1800，相似活动起始时间跨度 |
| `attack_campaign_window_seconds` | 3600，攻击活动候选起始时间跨度 |
| `campaign_window_seconds` | 弃用，仅未指定上一项时作为其兼容别名；不控制会话 |
| `suspicious_min_score` | 45，有规则命中时不受此门槛限制 |

```json
{
  "output": {
    "format": "parquet",
    "require_parquet": true,
    "batch_size": 1000,
    "batch_bytes": 8388608
  }
}
```

由 format 决定实际格式，使用 parquet 或调试用 jsonl。Parquet 缺少 pyarrow 会失败，不自动回退；require_parquet 是保留字段，当前写入器不独立依靠它判断格式。达到任一缓冲门槛就写一批，字节门槛是字符串估算，不是进程内存上限。

### 5.2 资产与共享出口

```json
{
  "asset_ids": {"10.0.0.2": "asset-payment-01"},
  "asset_risk": {"asset-payment-01": 20},
  "shared_egress_ips": ["10.0.0.1"],
  "whitelist_ips": [],
  "trusted_networks": []
}
```

用真实资料替换示例。asset_ids 为目标 IP → 稳定资产 ID；shared_egress_ips 为日志中观察到的 NAT/代理共享来源 IP，不是受害服务器 IP。共享出口不是白名单，仍检测但关联更保守。无可靠信息时保持空列表/字典。

### 5.3 LLM 和中转站

当前客户端调用 `POST {base_url}/chat/completions`，使用 Bearer 密钥，读取 `choices[0].message.content` 中的 JSON 对象。服务须兼容此接口；仅支持其他协议的服务不能直接接入。

```json
{
  "enable_l3_semantic_judge": true,
  "l3_max_ratio": 0.001,
  "llm": {
    "enabled": true,
    "base_url": "https://your-provider.example/v1",
    "model": "MODEL_ID_FROM_PROVIDER",
    "api_key": "YOUR_API_KEY",
    "timeout_seconds": 60,
    "max_concurrency": 4,
    "max_consecutive_failures": 3,
    "max_retries": 1
  }
}
```

以上均为占位符。base_url 填服务 API 根地址，不是控制台网页；若完整接口为 `https://host/v1/chat/completions`，填 `https://host/v1`，避免重复路径。当前直接读取 api_key，不读取 api_key_env。真实密钥配置不要提交或分享。

本项目的本地 `llama-server` 以 `-np 4` 启动，因此 `llm.max_concurrency` 默认设为 4，与可用推理槽位对齐。超过 4 只会让请求在服务端排队，并不会提升本地吞吐；若要继续增加，需要先确认显存/内存余量并同步调整模型服务的并行槽位。

LLM 需要 enabled=true、非空 key 和 model；L3 还需顶层 enable_l3_semantic_judge=true 且有候选。只启用开关不代表成功调用。不用模型时将 llm.enabled 和 enable_l3_semantic_judge 设为 false，其他本地处理可继续使用。

映射可用独立小模型：

```json
{
  "mapping_llm": {
    "enabled": true,
    "base_url": "https://your-provider.example/v1",
    "model": "MAPPING_MODEL_ID",
    "api_key": "YOUR_MAPPING_API_KEY",
    "timeout_seconds": 30
  }
}
```

无 mapping_llm 时复用 llm；显式设置 mapping_llm.enabled=false 后，映射只用规则，不回退到 L3 模型。缓存命中无需再次调用。

## 6. IOC 情报与更新

### 6.1 本地 SQLite 库

```json
{"local_ioc": {"enabled": true}}
```

库为 `shared-workspace/m1/local_ioc/ioc.sqlite3`，报告为同目录 update_status.json。无需 LLM/微步密钥；每批开始加载快照，逐事件匹配不联网。

| 来源 | 内容与地址 |
| --- | --- |
| Spamhaus DROP IPv4 | [IPv4 网段](https://www.spamhaus.org/drop/drop_v4.json) |
| Spamhaus DROP IPv6 | [IPv6 网段](https://www.spamhaus.org/drop/drop_v6.json) |
| OpenPhish Community | [钓鱼完整 URL](https://openphish.com/feed.txt) |

源/目的 IP 按网段索引匹配，完整 URL 精确匹配；仅 `/login` 无法匹配完整网址，不自动扩展为整域名黑名单。数量随更新变化，以报告为准；再分发时保留来源并核对提供方条款。

双击根目录 update_ioc.bat，或运行：

```powershell
python -m m1.local_ioc --workspace .\shared-workspace
```

脚本自动定位 Python/目录并保留结果窗口；不要移动脚本，桌面使用快捷方式。`update_ioc.bat --check` 只检查环境。同一时间只运行一个更新任务。建议每天更新，当前未设置后台定时任务。

暂存 SQLite 更新后原子替换。单来源失败保留旧数据，其他来源可更新，命令非零退出码提示未全部成功。下载成功设 72 小时本地有效期，过期记录不被新批次加载；保留旧记录不会延长有效期。该时间不是上游首次发现时间。批次中途更新不改变已加载快照，缺失/过期状态见 status.local_ioc。

### 6.2 手工 IOC

```json
{
  "ioc_ips": ["203.0.113.10"],
  "ioc_domains": ["malicious.example"],
  "ioc_urls": ["https://malicious.example/payload"]
}
```

示例是文档占位指标，不是真实情报。手工 IP 填精确地址，不填 CIDR；域名不带协议或路径，不自动匹配所有子域；URL 精确匹配。手工集合没有自动有效期，需自行维护。

### 6.3 微步在线（可选）

```json
{
  "threatbook": {
    "enabled": true,
    "api_key": "YOUR_THREATBOOK_KEY",
    "timeout_seconds": 5,
    "max_queries_per_batch": 200,
    "cache_ttl_seconds": 86400,
    "query_ip_reputation": true,
    "skip_private_ips": true
  }
}
```

使用代码中的固定 IP 信誉接口，只查询源 IP，先读缓存，默认跳过私网。查询在逐事件处理路径执行，无缓存且网络慢时会拖慢导入。没有密钥不生效，失败时保留本地检测结果并记录降级。

max_queries_per_batch 是客户端查询计数上限，不是精确唯一 IP 数或账单数；失败 IP 可能再次尝试，业务错误计数也可能与 HTTP 次数不同。状态见 status.threatbook。

## 7. 输出与 M2 对接

每次输出在 `shared-workspace/m1/ready/<batch_id>/<run_id>/`，实际文件名以 batch.json.artifacts 为准。下表按 Parquet 配置展示。

| 文件 | 内容及条件 |
| --- | --- |
| `event_details.parquet` | 通过过滤的已解析事件明细与载荷，按 event_id 查询 |
| `all_sessions.parquet` | 全部保留事件的聚合会话，供审计 |
| `suspicious_events.parquet` | M2 主要输入；零条时也生成空文件 |
| `activity_groups.parquet` | 多路径等相似活动候选，允许为空 |
| `attack_campaigns.parquet` | 资产/服务/类别约束下的活动候选，允许为空 |
| `review_groups.parquet` | 跨会话的同类告警复核队列，保留所有成员引用；不是攻击事件合并 |
| `l3_candidates.parquet` | 有候选时生成，不证明 LLM 已成功执行 |
| `semantic_judgements.parquet` | 至少一个合法研判结果时生成 |
| `mapping_plans/*.json` | 本次映射方案及 Schema Profile |
| `status.json` | 数量、模块执行状态、调用统计、L2 策略 |
| `batch.json` | SuspiciousEventBatch 清单、映射、运行标识和文件元数据 |
| `READY.json` | 发布标记，含 batch.json 的 SHA-256 |

SuspiciousEventBatch 是结构化交付包，不是 ZIP。“压缩”主要指过滤、会话聚合及载荷分离；Parquet 另用 Snappy 压缩。条数减少不等于准确率提高。

先写 staging，关闭文件、检查行数和校验和，再同文件系统重命名发布。M2 只消费带 READY.json 且校验通过的目录。重跑是新投递，consumption_key 为 batch_id:run_id；M2 自行持久化消费记录，并结合指纹、时间、资产去除跨运行重复。

```python
from pathlib import Path
from m1.handoff import read_batch, iter_suspicious

# 替换成运行命令打印的真实目录。
directory = Path('shared-workspace/m1/ready/batch-excel-001/<run_id>')
batch = read_batch(directory)
for session in iter_suspicious(directory, batch_size=1000):
    print(session['session_id'], session['risk_score'], session['ioc_matches'])
```

查看一个会话全部载荷应按 related_event_ids 查询，不只是代表事件 event_id：

```python
import pyarrow.parquet as pq

# directory、batch 和 session 来自上例；需至少存在一个会话。
details = pq.read_table(
    directory / batch['artifacts']['event_details'],
    filters=[('event_id', 'in', session['related_event_ids'])],
)
print(details.to_pylist())
```

Parquet 的 rule_hits/ioc_matches/evidence 等是原生 List/Struct，不用 json.loads；语义结果按 session_id 联接。domains/paths 各最多 50 项，另有完整数量字段，超出时回查明细。详见 [交付契约](SuspiciousEventBatch.md)。

## 8. 状态与排错

优先查看本次目录的 status.json：

| 字段 | 含义 |
| --- | --- |
| `rule_version` / `l2_policy` | 实际执行规则及 L2 参数，区分新旧批次 |
| `metrics.input_records` | 解析器产出的记录数，不含表头和跳过的 Excel 空行 |
| `metrics.filtered_*` | 各过滤计数，未发生时部分键可能不存在 |
| `metrics.normalized_records` | 当前实现统计过滤后保留数量 |
| `metrics.all_sessions` / `suspicious_sessions` | 基础会话数和可疑会话数 |
| `aggregation.grouped_sessions` | 相似活动覆盖的唯一会话数 |
| `local_ioc` | 库状态、有效及过期指标数 |
| `llm_mapping_calls` | 映射尝试数；缓存命中可为 0 |
| `metrics.l3_candidates` / `l3_judgements` | 候选数和通过校验的语义结果数 |
| `llm_attempts` / `llm_retries` | 请求尝试及重试数 |
| `llm_calls` | 客户端解析出 JSON 对象的返回计数，不等于有效研判数 |
| `l3_status` | disabled/no_candidates/completed/partial_failure/failed |
| `semantic_counts` | 可疑会话语义执行状态汇总 |

READY 表示文件可交付，不保证全部模型请求成功。running 文件是开始标记，不持续刷新逐条百分比；L3 进度显示在终端。处理阶段失败一般写 failed 状态，启动前校验错误也可能只显示在终端。

| 现象 | 检查方法 |
| --- | --- |
| No module named m1 | 切回包含 m1 文件夹的根目录，使用 python -m m1.run |
| 找不到 openyxl/openxyl | 正确包名 openpyxl：python -m pip install openpyxl |
| 安装 pyarrow 后仍找不到 | 用 `python -c "import sys, pyarrow; print(sys.executable)"` 确认运行环境 |
| LLM 配好仍没结果 | 检查开关、key/model、候选预算、l3_status；映射缓存命中也不调用 |
| 401/403/404 | 检查密钥、权限、模型 ID、base_url，不只增加超时 |
| L3 长时间等待 | 查看服务延迟、超时、重试和并发；停提交后仍等待在途请求 |
| IOC 没命中 | 检查有效期、源/目的 IP、完整 URL；无命中不等于安全 |
| 新文件没处理 | 加入 Manifest，仅放进 incoming 不会自动执行 |
| 输出数字仍是旧的 | 查看终端打印的新 run_id 目录，旧文件不会自动更新 |

## 9. 验证与已知边界

离线回归测试，不调用真实 LLM：

```powershell
python -m unittest tests.test_quality tests.test_l2 tests.test_local_ioc tests.test_m1 tests.test_rule_quality tests.test_handoff
```

隔离检查现有 Excel：

```powershell
python -m tests.check_duties
```

脚本使用独立配置，关闭外部模型和情报查询，校验引用、计数、评分，结束清理临时结果，不覆盖正式批次。最近规则 1.3 验证：39 项测试通过；11,000 条 Excel 输入形成 10,955 个基础会话、5,697 个可疑会话、5,563 个活动候选。该结果不是当前配置的在线全量重跑，也不是准确率评测。

可选合成性能检查：

```powershell
python -m tests.benchmark_schema --rows 100000
```

报告写 tests/schema_benchmark_result.json，耗时与内存取决于机器、载荷和关联数量，不沿用旧版数字作为保证。

当前限制：

- 轻量事件、去重集合和关联索引仍随数据量占用内存；JSON 数组、XLS、PCAPNG 不是完全流式解析。
- 规则和扫描是启发式，低速、分布式、非敏感路径、共享出口跨连接扫描可能漏检，正常管理行为也需复核。
- LLM 证据被截断，不读取全部成员载荷，置信度未经标注集校准。
- 映射是单文件方案，未映射的原列不保证进入明细，原文件应保留。
- 关联候选不确认同一攻击者；source_role/direction 为未确认/未知，tactic_candidates 留空供 M2 增强。
- IOC 不含文件哈希，不自动查询 DNS。
- 没有后台定时服务、M2 消费事务或自动处置功能；目录监听须显式启动 intake。API 也需显式启动，单进程单任务执行，不是分布式调度器。

## 10. 复核降噪与准确率评估

### 当前载荷相似度版本：payload-simhash-v1

当前启用无需训练及第三方依赖的 SimHash 近似检索，随后以哈希化词三元组集合的 Jaccard 相似度 ≥ 0.90 校验。每条最多比较 64 个候选，分桶列表也限制为 64；这是有界近似检索，可能漏掉本应相似的记录，不保证全局最优聚类。与固定锚点比较，不采用容易形成相似度链式扩张的连通分量合并。

特征在丢弃完整内存载荷前生成，包含 URL 查询参数、请求体、日志消息及 User-Agent。空白归一化，不自动解码、不小写化、不把数字或运算符替换为通配符。每字段最多取 4096 字符做特征，集合最多 256 个特征；超过任一上限时禁止近似归并，只用整个空白归一化内容的 SHA-256 摘要精确归组。短文本少于 8 个特征也只精确归组。空白变化在某些语言中具有语义，所有分组仍只用于复核展示。

一条会话含多个不同载荷时，用完整成员摘要集合标识，不拿第一条或最高分片段代替整条会话做近似归并。旧结果没有完整特征时独立保留，不能把截断的 semantic_evidence 当完整载荷证明。内部 token 集合不会写入输出 Parquet，也不会发送给模型；每组写 similarity_version，status.quality.payload_similarity 记录比较次数及近似归组数。

L3 优先覆盖新的载荷复核组，同路径的不同载荷因此有机会分别入选。候选仍不超过原始事件 1%，本次没有调整现有调用比例，没有把代表模型结论扩散到全组。

**最新离线验证**：55 项测试通过。11000 条输入仍保留 10955 个基础会话、5697 个可疑会话；按载荷比较后形成 5084 个复核组，展示压缩 10.76%，执行 3231 次候选校验、506 次近似归组。相比下文历史的 1645 组，此版本主动拆开不同载荷，不能把旧版 71.1% 压缩率当作当前效果或检测准确率。全部成员引用校验通过，加载 2104 条有效本地 IOC，未调用真实 LLM；本次审计保存在 work/quality-audit 下的新目录，旧批次不覆盖。

本次没有安装 CatBoost、Isolation Forest、LogBERT 或 Drain3。训练标签、稳定正常基线和连续日志序列尚不充分；当前不会让未经验证的模型过滤告警。也没有仅为采用新技术替换现有 Excel/Parquet I/O 引擎。后续是否引入这些方法，以标注评估和性能瓶颈为依据。

回归命令：

```powershell
python -m unittest tests.test_similarity tests.test_quality tests.test_api tests.test_intake tests.test_l2 tests.test_local_ioc tests.test_m1 tests.test_rule_quality tests.test_handoff
```

基础五元组会话不为追求压缩率强行合并。`review_groups.parquet` 先按规则集合、协议、方法、路径模板和 IOC 指标划分候选范围，再按载荷相似度细分，供界面折叠近似告警。分组可以跨来源、资产和时间，因此 `correlation_status=review_pattern_only`，不能据此确认同一攻击者或一次安全事件。查询成员用 `related_session_ids`，会话中保存 `review_group_id`；所有可疑会话仍完整输出。

代表会话选择组内最高分，仅用于优先复核，不证明整组相同恶意性。URL 查询部分现在参与载荷比较，不再仅凭去掉 query 后的路径模板合并。近似比较仍可能将语义不同但文本相似的载荷分到一起，需查询成员证据；此功能不删除会话、不减少实际攻击数量，也不直接丢弃疑似误报。

L3 在保留规则类别代表的基础上，优先选择不同复核模式，再用剩余预算补充重复模式，避免有限请求集中于同类告警。模型结论不传播给未调用的同组会话。保留现有 `l3_max_ratio=0.001`；需要扩大覆盖时可逐步提高到 `0.005` 或最高 `0.01`，但会增加调用量、耗时和费用，不能超过原始事件的 1%。

`status.quality` 记录复核组数、展示压缩率、可疑占比、成功 L3 会话覆盖率和选中模式数。`accuracy_status=requires_human_labels` 表示尚不能给出真实准确率。

生成使用实际本地 IOC、关闭模型和在线查询的独立复核批次：

```powershell
python -m tests.audit_quality
```

输出保存在 `work/quality-audit/<audit_id>/`，包括新批次、`report.json`、`review_labels.csv`。真实密钥不会复制到审计配置；它不会覆盖正式批次。此次验证加载 2104 条有效 IOC，11000 条输入形成 10955 个基础会话、5697 个可疑会话，整理为 **1645 个复核组（展示条目减少 71.1%）**。成员引用校验通过，42 项回归测试通过。真实 LLM 未调用，以上不代表模型准确率或 IOC 必然命中。

也可对任意已发布批次生成标签表（将占位路径替换为实际路径）：

```powershell
python -m m1.quality sample --batch "shared-workspace/m1/ready/<batch_id>/<run_id>" --labels "work/review_labels.csv" --per-class 100
```

工具分别从可疑与未入选会话中随机抽样，固定随机种子便于同一批次复现。每类默认最多 100 条，同时检查误报和漏报；CSV 包含批次身份、会话 ID、分层总量和样本量。已存在的标签表不会覆盖。用 Excel 编辑 `label`：真实攻击填 `malicious`，正常行为填 `benign`，无法确认填 `unknown`；不允许用现有规则分数或模型输出自动当作真实标签。`notes` 记录判断依据，并通过会话 ID 回查完整明细。

完成后运行：

```powershell
python -m m1.quality evaluate --batch "shared-workspace/m1/ready/<batch_id>/<run_id>" --labels "work/review_labels.csv"
```

输出 TP/FP/TN/FN、precision、recall、false_positive_rate 和 accuracy。未填或 unknown 不计入指标，分母为零返回 null；错误批次、未知/重复会话会被拒绝。预测以批次实际可疑文件为准，不信任 CSV 中可编辑的 predicted 列。指标只描述已标注样本，分层抽样比例和未完成标签会影响结果，不能直接宣传为全量准确率。该评估针对过滤后会话，不覆盖被白名单/去重等步骤移除的原始记录。

下一轮规则调优应依据人工确认的误报与漏报样例，保留独立验证样本；没有标签之前不自动提高阈值或删告警，以免把未知攻击压掉。
