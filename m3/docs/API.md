# NetGuard M3 接口文档

版本：当前实现 v0.1.0；整理日期：2026-09-20。

本文依据 `server.py`、`workspace_io.py`、`m3_services.py`、`contracts.py`、`retention.py` 编写。适用于前端接入、M1/M2 文件联调及测试验收。共享文件字段为仓库当前草案，尚需 M1/M2 团队确认。演示生产器不分析上传内容，不能用于证明检测效果。

## 1. 接入约定

| 项目 | 约定 |
|---|---|
| 本地地址 | `http://127.0.0.1:8001` |
| API 前缀 | `/api/v1`；健康检查为 `/health` |
| 在线描述 | `/docs`、`/redoc`、`/openapi.json` |
| 请求体 | 默认 `application/json`；文件上传为 `multipart/form-data` |
| 响应 | JSON、SSE 或下载文件，具体见接口定义 |
| 成功状态 | 当前所有业务接口成功均为 HTTP 200，包括创建任务和上传 |
| 标识符 | 新建 `file_id`、`task_id` 为 UUID 的 32 位十六进制字符串；告警/攻击链 ID 由 M2 提供 |
| 时间 | M3 的 `created_at`、审计和历史时间为带时区 ISO 8601；上传时间为 Unix 秒数 |
| 身份 | 当前为本地单用户模式，无登录鉴权接口；审计 actor 取 `NETGUARD_ACTOR`，默认 `local-user` |
| 分页 | 任务列表、告警列表、已读列表无服务端分页或筛选参数 |

普通业务错误为 `{"detail":"错误说明"}`。请求参数校验失败返回 HTTP 422，`detail` 为 FastAPI 校验错误数组，包含 `loc`、`msg`、`type` 等字段，不是字符串。接口没有统一的 `code/data/message` 外包装。

OpenAPI 可用于查询路由及输入模型，但多数响应未声明完整模型；本文补充其实际返回字段。`contracts.py` 中旧展示模型不能代替文件协议校验器，例如实际 bundle 支持 `info` 严重等级。

## 2. 接口总表

下表路径除 `/health` 外均相对于 `/api/v1`。

| 方法 | 路径 | 功能 |
|---|---|---|
| GET | `/health`（无 API 前缀） | 服务健康状态 |
| POST | `/files` | 上传单个文件 |
| POST | `/tasks` | 创建分析任务并投递文件 |
| GET | `/tasks` | 列出全部任务 |
| GET | `/tasks/{task_id}` | 查询任务与最新结果 |
| POST | `/tasks/{task_id}/retry` | 重试失败任务 |
| GET | `/tasks/{task_id}/stream` | 订阅任务进度 SSE |
| GET | `/tasks/{task_id}/alerts` | 获取任务告警 |
| GET | `/tasks/{task_id}/bundle` | 获取经校验和脱敏的结果包 |
| GET | `/attack-chains/{chain_id}` | 查询攻击链详情 |
| POST | `/chat` | 任务范围问答 SSE |
| GET | `/reports/{task_id}` | 下载 JSON/PDF 报告 |
| POST | `/tasks/{task_id}/view-alert/{alert_id}` | 标记告警已读 |
| GET | `/read-alerts` | 获取已读记录 |
| GET | `/tasks/{task_id}/audit` | 最近 100 条任务审计 |
| GET | `/tasks/{task_id}/chat-history` | 最近 50 条对话历史 |

## 3. 数据对象

### 3.1 文件记录 FileRecord

| 字段 | 类型 | 说明 |
|---|---|---|
| file_id | string | 上传文件标识 |
| filename | string | 原文件名 |
| size | integer | 原始字节数，1～2147483648 |
| sha256 | string | 原始字节 SHA256，64 位小写十六进制 |
| uploaded_at_epoch | number | 上传完成时的 Unix 秒数 |
| raw_expired | boolean | 保留策略清理后内部记录可能增加此标记；上传响应不含该字段 |

### 3.2 任务对象

| 字段 | 类型 | 说明 |
|---|---|---|
| task_id / file_ids | string / string[] | 任务 ID / 文件 ID 列表 |
| query | string | 用户分析备注，默认空字符串 |
| filename | string | 第一个上传文件的原始名称 |
| created_at | string | 创建时间 |
| status | string | `queued/running/completed/failed` |
| progress | integer | 0～100；失败时可能保留失败前进度 |
| stage | string | 阶段或失败原因，供直接展示 |
| mock / transport | boolean / string | 当前创建值固定为 `false` / `files`；mock=false 不证明上游结果是真实分析 |
| alerts | object[] | 映射后的告警，未取得有效结果时为空 |
| chains / chain | object[] / object或null | 全部攻击链 / 第一条攻击链，未取得结果时为空数组/null |
| module_statuses | object[] | 刷新后提供，状态原字段加 `module: m1或m2` |
| bundle | object | 仅有有效结果时提供；包含画像、证据、指标和报告 |
| degraded | boolean | 读取有效 bundle 后赋值，表示结果包降级，不等同于问答降级 |

查询、列表、SSE 等访问会重新读取文件状态。失败分支不保证重置 `progress` 和 `degraded`，客户端应以 `status` 及当前有效结果为准。

状态计算顺序：任一模块 `FAILED` → 任务 failed；否则有合法 bundle → completed、100%；否则有模块状态 → running，进度为 `min(99, round((M1进度+M2进度)/2))`，缺失模块按 0 计；否则 queued、0%。文件解析或契约校验异常也使任务 failed。模块仅写 COMPLETED 或 DEGRADED 不会直接完成任务。

### 3.3 告警与攻击链

告警保留 bundle 原字段，并补充 `schema_version`（缺省 CandidateAlert.v1）、`mitre`（原值或 technique）、`evidence`（event_ids 对应证据摘要，以 `; ` 连接）。核心字段为 `alert_id/title/severity/event_ids`；严重等级支持 `info/low/medium/high/critical`。可选字段包括 `source/target/timestamp/tactic/technique/confidence/attack_type/risk_reason/vulnerabilities/recommended_actions`。

攻击链保留 `chain_id/severity/stages/edges` 及扩展字段，补充 `schema_version`（缺省 AttackChain.v1）、`task_id`、`nodes`（stage_id 列表）、`evidence_ids` 和 `evidence_event_ids`（各阶段证据去重）、`explanation`（报告 summary）。时间、阶段和引用要求见第 6 节。

## 4. HTTP 接口详情

### 4.1 GET /health

无参数。200 示例：

```json
{"status":"ok","mode":"shared_files","llm":"disabled"}
```

`NETGUARD_LLM_ENABLED=1` 时 llm 为 `configured`，只表示配置开关，不检测模型或 M1/M2 可用性。

### 4.2 POST /api/v1/files

表单字段 `file`，必填，一次一个文件。支持 `.csv/.json/.jsonl/.pcap/.pcapng/.xlsx`，扩展名大小写不敏感。返回 FileRecord。

```json
{"file_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","filename":"events.csv","size":42,"sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","uploaded_at_epoch":1789862400.0}
```

示例 ID、大小、摘要均为占位值，实际由上传字节生成。

| 条件 | HTTP | detail |
|---|---|---|
| 扩展名不支持 | 400 | `FILE_400: 不支持该格式` |
| 零字节 | 400 | `文件为空` |
| 超过 2×1024³ 字节 | 413 | `文件超过 2 GB` |
| 内容头/归档检查失败 | 400 | 校验器的具体原因 |
| 缺少 file | 422 | 校验错误数组 |

内容检查：PCAP 检查魔数和至少 24 字节；PCAPNG 检查魔数和至少 28 字节；XLSX 检查 ZIP、必要成员 `[Content_Types].xml` 与 `xl/workbook.xml`，成员数≤10000、总解压大小≤512 MiB、每成员压缩比≤500。文本仅检查前 65536 字节中的 NUL 和明显非文本头；JSON/JSONL 首个有效字符须为 `{` 或 `[`。当前不完整解析 JSON、CSV、抓包或工作簿，上传成功不代表语法完整或可分析。上传失败会移除已创建的临时原始副本。

### 4.3 POST /api/v1/tasks

| 请求字段 | 类型 | 必填 | 约束 |
|---|---|---|---|
| file_ids | string[] | 是 | 至少 1 项，均为已上传且未过期的文件 |
| query | string | 否 | 默认 `""`，当前无长度限制 |

```json
{"file_ids":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"query":"分析认证失败事件"}
```

200 返回任务对象，初始 `status=queued`、`progress=0`、`stage=等待 M1/M2 文件结果`。M3 已将输入目录原子发布到共享区，不会自行执行检测算法。

错误：未知 file_id → 400 `FILE_400: 文件不存在`；过期副本 → 410 `原始副本已按保留策略过期，请重新上传`；文件投递/摘要校验失败 → 400 `任务文件投递失败：...`；空数组或缺少必填字段 → 422。没有幂等键，重复请求会产生不同任务；重复 file_id 当前未显式禁止。

### 4.4 GET /api/v1/tasks 与 GET /api/v1/tasks/{task_id}

列表无参数，200 返回任务数组，可能为 `[]`；无排序保证。详情路径参数 task_id 必填，200 返回任务对象。未知任务统一返回 404 `TASK_404`。

### 4.5 POST /api/v1/tasks/{task_id}/retry

无请求体。仅允许当前 failed 任务。复制原任务的 file_ids 和 query，创建并返回新任务对象、新 task_id；旧任务保留。

错误：未知任务 404；非失败任务 409 `只有失败任务可以重试`；复用文件已过期 410；其他创建失败同 4.3。failed 是文件刷新结果，若上游随后恢复，重试请求可能得到 409。

### 4.6 GET /api/v1/tasks/{task_id}/alerts

200 返回告警数组；等待、处理中或失败任务返回 `[]`，不是 409。未知任务 404。

### 4.7 GET /api/v1/tasks/{task_id}/bundle

200 返回合法且经过脱敏的 AttackChainBundle.v1，结构见第 6 节；无有效结果返回 `{}`，不是 409。未知任务 404。不得将空对象解释成“分析正常、没有风险”。

### 4.8 GET /api/v1/attack-chains/{chain_id}

遍历任务并刷新状态，200 返回匹配链对象。不存在返回 404 `攻击链不存在`。chain_id 是全局查询键，建议生产者采用跨任务唯一 ID，避免不同任务同名时命中首个结果。

### 4.9 GET /api/v1/reports/{task_id}?format=json

查询参数 format 为字符串，默认 `json`；仅支持精确小写 `json/pdf`。

| format | Content-Type | 响应内容 |
|---|---|---|
| json | application/json | 完整任务快照，包含有效 bundle，非单独 report 字段 |
| pdf | application/pdf | 中文风险报告、摘要、告警、降级状态、统计、版本、建议来源及证据 |

均设置 `Content-Disposition: attachment; filename="report-{task_id}.{format}"`。

错误：未知任务 404；任务未 completed → 409 `任务尚未完成`；completed 任务使用其他格式 → 400 `仅支持 json/pdf`。实现先检查任务完成再检查格式。完成任务的导出请求会写审计，包含随后因格式无效而失败的请求。

### 4.10 POST /api/v1/tasks/{task_id}/view-alert/{alert_id}

无请求体。200 返回 `{"ok":true}`。已读记录以 `(task_id,alert_id)` 唯一，重复调用不增加已读行，但每次都新增 `alert.view` 审计。未知任务 404 `TASK_404`；当前任务内无该告警 404 `告警不存在`。

### 4.11 GET /api/v1/read-alerts

无参数，返回所有任务已读记录，无顺序保证：

```json
[{"task_id":"TASK_ID","alert_id":"ALERT_ID"}]
```

### 4.12 GET /api/v1/tasks/{task_id}/audit

返回最近最多 100 条记录，按 at 降序；未知任务 404。

```json
[{"at":"2026-09-20T00:00:00+00:00","action":"task.created","detail":"{\"actor\": \"local-user\", \"detail\": \"\"}"}]
```

detail 是 JSON 编码的字符串，需要二次解析。动作包括 `task.created/alert.view/chat.query/report.export`。`raw.expired` 使用空 task_id，因此不出现在具体任务审计中。

### 4.13 GET /api/v1/tasks/{task_id}/chat-history

返回最近最多 50 条，按时间从旧到新排列；未知任务 404，无历史返回 `[]`。

每项为 `at/question/answer/citations`。citations 是 JSON 编码字符串，解析后为引用数组（见 5.2）；question 为脱敏后的用户问题。数据库不额外保存 chain_id 或此次回答的 degraded 字段。

## 5. SSE 接口

SSE 每条消息为 `event: 事件名`、`data: JSON`，以空行结束。客户端应按事件边界解析，不能将网络分块当成消息边界。

### 5.1 GET /api/v1/tasks/{task_id}/stream

无请求体，成功为 `text/event-stream`，`Cache-Control: no-cache`。未知任务在建立流前返回 404 JSON。每 0.25 秒刷新文件状态，仅快照变化时发送；连接建立后发送当前快照，终态 completed/failed 发出后关闭。

```text
event: progress
data: {"task_id":"TASK_ID","status":"running","progress":20,"stage":"M1 降噪中","schema_version":"Status.v1","module_statuses":[{"schema_version":"Status.v1","task_id":"TASK_ID","state":"RUNNING","progress":40,"message":"M1 降噪中","module":"m1"}]}

```

外层使用 `status` 小写状态，模块文件使用 `state` 大写状态，虽然 schema_version 都叫 Status.v1，结构并不相同。实现没有 SSE id、历史回放、心跳或 Last-Event-ID 恢复；重新连接获取当前快照。无状态变化时连接可能一直静默；收到终态后客户端应主动关闭 EventSource。

### 5.2 POST /api/v1/chat

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| task_id | string | 是 | 必须为 completed 任务 |
| chain_id | string或null | 否 | 限定当前任务中的攻击链；默认 null |
| message | string | 是 | 长度 1～4000；当前不剔除纯空白 |

```json
{"task_id":"TASK_ID","chain_id":null,"message":"总结并解释证据"}
```

返回 `text/event-stream`，事件顺序如下：

```text
event: status
data: {"message":"正在检索任务证据与知识来源"}

event: delta
data: {"text":"【本地检索与统计回答，LLM 未启用或不可用】..."}

event: evidence
data: {"items":[{"alert_id":"event-TASK_ID","evidence":"演示：SSH 认证重复失败","source_type":"task_evidence"}]}

event: done
data: {"degraded":true}

```

delta 可多次出现，每段最多 80 个字符。当前先取得完整回答再分段推送，并非模型逐 token 转发。evidence.items 的字段名虽为 alert_id，值实际可能是证据 event_id 或知识条目 ID；source_type 为 `task_evidence/knowledge`。没有匹配证据时明确说明，引用数组可以为空。

错误（流建立前）：未知任务 404；未完成 409 `请等待任务完成`；chain_id 不属于任务 404 `攻击链不属于当前任务`；消息长度越界/必填字段缺失 422。流内目前没有标准 error 事件，客户端应识别未收到 done 的异常中断。

模型未启用、调用失败或引用校验失败时，本地检索回答并返回 done.degraded=true。它与 bundle.degraded 是独立概念。浏览器原生 EventSource 不支持 POST，请使用 fetch 读取响应流。历史记录在 delta 推送前入库；客户端中断不保证没有历史记录。

## 6. M1/M2 共享文件接口

### 6.1 目录与发布

```text
<NETGUARD_WORKSPACE>/
  m3/STAGING/<task_id>/             # M3 写入中的输入
  m3/READY/<task_id>/manifest.json  # 输入清单
  m3/READY/<task_id>/<file_id>       # 无扩展名原始副本
  m1/STATUS/<task_id>/status.json   # M1 状态
  m2/STATUS/<task_id>/status.json   # M2 状态
  m2/STAGING/<task_id>/             # M2 写入中的结果
  m2/READY/<task_id>/manifest.json  # 结果摘要清单
  m2/READY/<task_id>/bundle.json    # 完整结果
```

先写 STAGING，flush/fsync 后原子改名到 READY；状态文件先写临时文件再原子替换。READY 为完整、不可变结果，不在该目录持续修改。M3 不消费 M1→M2 中间产物，不向 M1/M2 发起 HTTP/RPC 请求。task_id 的路径约束为 `[a-zA-Z0-9_-]+`。

### 6.2 TaskManifest.v1（M3 输出）

```json
{
  "schema_version":"TaskManifest.v1",
  "task_id":"TASK_ID",
  "created_at":"2026-09-20T00:00:00+00:00",
  "source_files":[{"file_id":"FILE_ID","filename":"events.csv","size":42,"sha256":"实际64位摘要","uploaded_at_epoch":1789862400.0,"path":"FILE_ID"}],
  "user_prompt":"分析认证失败事件",
  "versions":{"rule_version":"unconfigured","model_version":"unconfigured","prompt_version":"unconfigured","code_commit":"unconfigured","threshold_version":"unconfigured"}
}
```

path 相对于该任务目录，原始格式依据 filename 判断。versions 取对应 `NETGUARD_RULE_VERSION/MODEL_VERSION/PROMPT_VERSION/CODE_COMMIT/THRESHOLD_VERSION` 环境变量，默认 unconfigured；M2 应提供自身实际处理版本。

### 6.3 Status.v1（M1/M2 输出）

```json
{"schema_version":"Status.v1","task_id":"TASK_ID","state":"RUNNING","progress":40,"message":"M1 降噪中"}
```

schema_version 与 task_id 必须匹配；state 为 `QUEUED/RUNNING/COMPLETED/FAILED/DEGRADED`，progress 在 0～100，约定为整数；message 建议提供。当前读取器仅对进度做范围判断，并未严格限制整数类型。

### 6.4 ResultManifest.v1（M2 输出）

```json
{"schema_version":"ResultManifest.v1","task_id":"TASK_ID","sha256":"bundle.json原始字节的64位小写SHA256"}
```

必须对最终写出的字节计算摘要，包括空白和换行，不能对重新序列化后的对象计算摘要。bundle 内 task_id 也必须一致。

### 6.5 AttackChainBundle.v1（M2 输出）

| 字段 | 必填 | 类型/默认 | 当前校验 |
|---|---|---|---|
| schema_version | 是 | string | 精确为 AttackChainBundle.v1 |
| task_id | 是 | string | 与请求任务一致 |
| versions | 是 | object | 下述 5 个键齐全且为非空白字符串 |
| evidence | 是 | object[] | event_id 为非空字符串，包内唯一 |
| alerts | 是 | object[] | 唯一非空 alert_id、字符串 title、合法 severity、非空 event_ids 且引用存在 |
| chains | 是 | object[] | 唯一 chain_id；合法 severity；stages 必填，edges 默认 [] |
| profiles | 否 | object[] / [] | 非空有效 evidence_refs；chain_ids 若有须可解析 |
| metrics | 否 | object / {} | 保留生产者字段，未强制具体统计结构 |
| report | 否 | object / {} | recommended_actions 中的 source 必须为规定枚举 |
| degraded | 否 | boolean / false | 结果降级标记 |

版本键：`rule_version/model_version/prompt_version/code_commit/threshold_version`；不适用可写 disabled，不能省略或空白。

stage 必填 `stage_id/tactic/technique/evidence_event_ids/confidence/time_range`。stage_id 链内唯一，证据引用非空且存在，confidence 在 0～1，time_range 为两个字符串，约定带时区 ISO 8601。当前尚未验证时间格式、先后顺序。edges 每项为两个有效 stage_id。当前允许空 stages，不额外判断自环或图环路。

告警可选 confidence 若提供须在 0～1。evidence 推荐附 `summary/source/target/timestamp/raw_ref`，raw_ref 推荐文件 ID、行号或包号。profile.relationships 若存在，每条需非空有效 evidence_refs。metrics 推荐 `raw_count/denoised_count/suspicious_count/duration_seconds/top_iocs`。

report 推荐 `summary/recommended_actions`，建议项 source 仅允许 `rule_based/knowledge_base/llm_generated/analyst_verified`；text 应填写建议内容，但当前校验器未强制其存在。告警自带 recommended_actions 未施加同等来源校验。扩展字段会保留。完整可执行演示见 `demo_bundle.py`，基础结构见 `schemas/AttackChainBundle.v1.json`，最终以 `workspace_io.Bundle` 的运行时引用检查为准。

任何摘要、版本或引用校验失败，任务标记 failed，清空有效 bundle/alerts/chains，防止错误证据被展示。不要仅凭 status.json 中的 COMPLETED 判定任务完成。

## 7. 保留、脱敏与配置

原始副本默认保留 72 小时，每 60 秒执行一次维护。引用该文件的任务只要有一个非 completed/failed 就保留；超过期限且无等待任务的文件可以清理，包括无任务引用的上传。清理 data 副本及 M3 READY/DONE 副本；不清理用户原文件或 M1/M2 自有目录。元信息标为 raw_expired，重建任务需重新上传。TTL≤0 关闭清理；缺上传时间的旧记录不自动清理。

bundle 在展示前递归脱敏特定敏感键、匹配的密码/token 文本和邮箱；历史问题也脱敏。上传原文、任务 query 等并不因此全量脱敏，不应将其理解为通用 DLP。

| 环境变量 | 默认/用途 |
|---|---|
| NETGUARD_DATA_DIR | 项目 data；文件副本与 SQLite |
| NETGUARD_WORKSPACE | 项目 shared_workspace；共享目录 |
| NETGUARD_RAW_TTL_HOURS | 72；原始副本保留小时 |
| NETGUARD_ACTOR | local-user；审计标识 |
| NETGUARD_LLM_ENABLED | 非 1 为关闭 |
| NETGUARD_LLM_BASE_URL | 启用时配置，以 /v1 结尾，实际请求追加 /chat/completions |
| NETGUARD_LLM_MODEL / NETGUARD_LLM_API_KEY | 模型名称 / 可选凭据 |

`.env.example` 仅为清单，服务不自动加载。当前接口没有取消任务、删除任务、原始文件下载、服务端筛选、用户权限和接口幂等功能。

## 8. 最小接入示例（PowerShell）

在仓库目录启动服务后，另开终端执行；文件路径替换为真实输入。

```powershell
$base = 'http://127.0.0.1:8001'
$uploaded = curl.exe -sS -F 'file=@events.csv' "$base/api/v1/files" | ConvertFrom-Json
$body = @{ file_ids = @($uploaded.file_id); query = '分析认证失败事件' } | ConvertTo-Json
$task = Invoke-RestMethod -Method Post -Uri "$base/api/v1/tasks" -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
Invoke-RestMethod "$base/api/v1/tasks/$($task.task_id)"
curl.exe -N "$base/api/v1/tasks/$($task.task_id)/stream"
# M1/M2 发布有效结果，任务 completed 后导出：
Invoke-WebRequest "$base/api/v1/reports/$($task.task_id)?format=json" -OutFile report.json
```

无 M1/M2 时任务会等待。独立测试使用临时共享目录中的演示生产器，参见 [测试用例](TEST_CASES.md)，不要把演示结果当成检测结果。
