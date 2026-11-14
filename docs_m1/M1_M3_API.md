# M1 ↔ M3 文件分析接口文档

接口版本：1.0。交付对象：M3 前后端开发者。实现入口：`m1/api.py`，批处理核心：`m1/run.py::process_task`。

## 1. 依据和待确认事项

用户提供的语雀地址是知识库协作邀请链接，当前访问返回登录页，未取得《网络攻击智能研判系统——详细架构与并行开发文档 v2.0》正文。因此本文是**根据现有 M1 实现及已确认模块职责形成的可运行联调契约**，不是声称已经逐项符合该架构文档。未保存或发布邀请令牌。

已知职责：M1 负责解析、标准化、过滤、去重、IOC、会话聚合、初筛评分和第一轮语义研判；M2 消费 SuspiciousEventBatch 并继续关联研判；本接口让 M3 选择共享目录文件、提交分析任务、轮询状态并获取交付路径。

待 M3 确认：共享目录挂载、服务地址、网关认证、统一任务 ID 映射、是否需要回调或消息队列、上传系统的原子落盘约定。M1 当前不实现账号体系、网页文件上传、任务取消、SSE/WebSocket、自动回调或多实例调度。

当前没有明确 M3 接收人或项目目录，本文作为可转交文件交付，未直接发送到外部系统。

## 2. 交互流程与职责

1. M3 完成上传，将文件保存到共享工作区的 `incoming/`。先使用 `.part` 临时后缀，关闭文件后重命名为正式后缀，避免读取半个文件。
2. M3 调用 `GET /v1/files` 显示文件列表，用户手动选择一个文件。
3. M3 用选中的 `file_id` 和唯一 `request_id` 调用 `POST /v1/tasks`。
4. M1 返回 202 和 `task_id`，单个后台工作线程排队执行；读取前检查文件版本并复制输入快照，调用内存任务对象进行分析。
5. M3 每 2～5 秒调用 `GET /v1/tasks/{task_id}`，直到成功或失败。
6. 成功后调用 `GET /v1/tasks/{task_id}/result`，得到相对共享工作区的目录及文件元数据。
7. M3 通知 M2 消费该目录；M2 仍按 `READY.json`/`batch.json` 及校验和检查完整性。

**用户无需创建 excel-001.json。** API 请求体就是任务描述，程序在内存中组织处理参数。服务仍保存任务状态数据库和输出 batch/status JSON，以便审计；共享的 `m1/config.json` 仍保留模型、IOC、规则等服务端配置。

输入文件、输出 Parquet 均走共享文件系统，HTTP 只传控制和元数据，不把大量原始日志塞进请求。没有直接下载任意服务器路径的接口。

## 3. 启动服务

项目根目录执行，使用现有 Python 环境：

```powershell
python -m pip install openpyxl pyarrow
python -m m1.api --workspace .\shared-workspace --host 127.0.0.1 --port 8765
```

也可双击 `start_m1_api.bat`，然后打开 `http://127.0.0.1:8765/`。内置页面提供文件选择、提交及状态轮询；它不替代 M3 上传界面。

默认仅本机访问。跨机器联调时，PowerShell 示例：

```powershell
$env:M1_API_TOKEN = "replace-with-a-long-random-service-token"
python -m m1.api --workspace .\shared-workspace --host 0.0.0.0 --port 8765
```

设置 M1_API_TOKEN 后，所有 `/v1/` 请求（含健康检查）必须带：

```http
Authorization: Bearer <M1_API_TOKEN>
```

这是 M1 服务令牌，不是 LLM API Key。非本机监听必须配置该令牌。根路径页面不含业务数据，可以打开，实际操作仍需认证。正式部署通过受控内网/HTTPS 反向代理访问，不将这个标准库 HTTP 服务直接暴露公网。M3 浏览器页面跨域时通过 M3 后端或同源网关转发；当前不提供开放 CORS。

`--max-pending` 默认为 20，统计 QUEUED+RUNNING，超过返回 429。M1 同一工作区只允许一个 API 服务实例，用 `m1/api/service.lock` 限制并行启动。按 Ctrl+C 停止接单并等待当前任务退出；排队任务不会自动重跑。

## 4. 接口清单

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/v1/health` | 服务和工作线程状态 |
| GET | `/v1/files` | 共享 incoming 文件列表 |
| POST | `/v1/tasks` | 选择一个文件并创建异步分析任务 |
| GET | `/v1/tasks/{task_id}` | 查询任务状态、错误和成功结果 |
| GET | `/v1/tasks/{task_id}/result` | 获取成功批次的位置和文件元数据 |

JSON UTF-8。任务创建只接受 application/json，最大请求体 16 KiB，不支持 chunked 请求体。未知路由返回 404；不支持的 HTTP 方法使用 HTTP 服务的 501 响应。

### 4.1 健康检查

```http
GET /v1/health
```

```json
{"api_version":"1.0","status":"ok","worker_alive":true}
```

成功响应 200。不代表依赖、LLM、微步、输入内容都可用，这些在任务执行时检查。

### 4.2 文件列表

```http
GET /v1/files
```

```json
{
  "files": [
    {
      "file_id": "<64位小写十六进制标识>",
      "name": "web_alerts.xlsx",
      "size_bytes": 123456,
      "modified_ns": "1770000000000000000",
      "format": "xlsx"
    }
  ]
}
```

只列 incoming 顶层支持的非空普通文件，跳过符号链接、临时名、隐藏名和 Excel 锁文件。支持 xlsx/xls/csv/json/jsonl/ndjson/pcap/cap/pcapng。列表根据扩展名筛选，实际内容由解析器验证；format 是后缀，不是内容检测结论。

`file_id` 是文件名、长度、修改时间的 SHA-256 版本标识，不是内容哈希。M3 必须原样使用返回值；同名文件修改后应刷新列表。它不能防御拥有共享目录写权限的人恶意保留时间戳并篡改内容，工作区写入者须可信。

文件列表不是上传完成证明。M3 必须完成上传后再发布正式文件名，并在任务提交至快照复制期间避免继续写同一文件。

### 4.3 创建任务

```http
POST /v1/tasks
Content-Type: application/json
```

```json
{
  "request_id": "m3-analysis-20260920-001",
  "file_id": "<从文件列表复制的file_id>",
  "options": {
    "session_window_seconds": 300,
    "profile_sample_size": 200
  }
}
```

| 字段 | 必填 | 约束 |
| --- | --- | --- |
| request_id | 是 | M3 生成，1～100 位英文字母、数字、下划线或连字符；网络重试时复用 |
| file_id | 是 | 列表返回的 64 位小写十六进制版本标识，只能选一个文件 |
| options | 否 | 省略或空对象使用服务端默认 |
| options.session_window_seconds | 否 | 整数 1～86400，会话相邻空闲窗口 |
| options.profile_sample_size | 否 | 整数 100～500，字段识别样本上限 |

不接受任意文件路径、模型密钥或其他未知配置项。布尔值不能冒充整数。M1 服务端配置控制模型与情报调用；点击开始分析可能触发真实服务费用。

首次提交返回 **202 Accepted**，结构示意：

```json
{
  "task_id": "api-<32位十六进制UUID>",
  "request_id": "m3-analysis-20260920-001",
  "state": "QUEUED",
  "created_at": "2026-09-20T00:00:00+00:00",
  "updated_at": "2026-09-20T00:00:00+00:00",
  "file": {"file_id":"<file_id>","name":"web_alerts.xlsx","size_bytes":123456,"modified_ns":"1770000000000000000","format":"xlsx"},
  "options": {"session_window_seconds":300,"profile_sample_size":200},
  "result": null,
  "error": null
}
```

相同 request_id 和相同 file_id/options 再提交返回 **200** 与原任务，不重复分析。相同 request_id 不同参数返回 409。options 的省略和空对象等价，但显式默认值与省略不是同一个请求。

需要主动重新分析时使用新 request_id。M3 在网络超时后不应立刻换 ID，否则可能创建重复任务。

### 4.4 任务状态

```http
GET /v1/tasks/{task_id}
```

200 返回与创建任务相同的任务记录结构。状态：

| state | 含义 | M3 行为 |
| --- | --- | --- |
| QUEUED | 已持久化，等待执行 | 继续轮询 |
| RUNNING | 复制快照或执行 M1 | 继续轮询，不显示虚构百分比 |
| SUCCEEDED | M1 已发布并校验批次 | 获取 result，交给 M2 |
| FAILED | 文件变更、执行失败或服务中断 | 展示 error，按需以新 request_id 重试 |

服务进程重启时，旧 QUEUED/RUNNING 会标为 FAILED/SERVICE_RESTARTED，不自动重复可能计费的调用。极端情况下批次已发布但状态未写回，重启仍可能标失败；管理员应检查 ready 后决定是否重试。本接口不承诺跨崩溃的 exactly-once。

正常关闭自动释放锁；强制结束后若锁残留，确认旧进程确实停止，再删除 `m1/api/service.lock` 并重启。不要在进程仍运行时删除锁。

### 4.5 成功结果

```http
GET /v1/tasks/{task_id}/result
```

成功返回 200：

```json
{
  "batch_id": "batch-api-<UUID>",
  "run_id": "<运行UUID>",
  "consumption_key": "batch-api-<UUID>:<运行UUID>",
  "directory": "m1/ready/batch-api-<UUID>/<运行UUID>",
  "artifacts": {
    "suspicious_events": {
      "path": "suspicious_events.parquet",
      "format": "parquet",
      "rows": 100,
      "bytes": 12345,
      "sha256": "<SHA256>",
      "layout_version": 2
    }
  },
  "metrics": {"input_records":1000,"normalized_records":950,"all_sessions":500,"suspicious_sessions":100,"attack_campaigns":90,"l3_candidates":1,"l3_judgements":1},
  "l3_status": "completed",
  "quality": {"accuracy_status":"requires_human_labels"}
}
```

上面仅展示部分 artifact/quality 字段，实际响应包括所有生成的文件元数据。directory 相对于 M1 的 `--workspace`，artifact.path 相对于 directory；M3/M2 应映射到自己的共享挂载根，不依赖 M1 本机盘符。

SUCCEEDED 表示本地交付成功，不保证 L3 全部成功。必须另外展示 l3_status（disabled/no_candidates/completed/partial_failure/failed）和 metrics.l3_judgements。可疑为零也是合法成功结果。

M2 继续使用 [SuspiciousEventBatch 契约](../m1/SuspiciousEventBatch.md)，按 consumption_key 管理消费幂等。本文 HTTP api_version=1.0 与交付 contract_version=2.0 是不同版本。

## 5. 错误与重试

错误响应（除标准 HTTP 501 外）：

```json
{"error":{"code":"FILE_CHANGED_OR_MISSING","message":"Refresh GET /v1/files and select again"}}
```

| HTTP | code | 处理建议 |
| --- | --- | --- |
| 400 | INVALID_REQUEST / INVALID_OPTIONS / INVALID_JSON | 修正请求结构 |
| 401 | UNAUTHORIZED | 检查 M1 服务令牌 |
| 404 | TASK_NOT_FOUND / NOT_FOUND | 核对 task_id 或路径 |
| 409 | FILE_CHANGED_OR_MISSING | 刷新文件列表，重新选择 |
| 409 | IDEMPOTENCY_CONFLICT | 同 request_id 参数不一致，确认是否应新建任务 |
| 409 | RESULT_NOT_READY | 先查询任务状态；FAILED 不会变成成功 |
| 413 | BODY_SIZE | 请求体须为 1～16384 字节 |
| 415 | CONTENT_TYPE | 使用 application/json |
| 429 | QUEUE_FULL | 等待后用同一个 request_id 重试 |
| 500 | INTERNAL_ERROR | 保留 request_id，检查服务后重试 |

任务异步失败通过 GET 返回 **HTTP 200 + state=FAILED**，error.code 可能是 FILE_CHANGED_OR_MISSING、PROCESSING_FAILED、SERVICE_RESTARTED。PROCESSING_FAILED 不向 HTTP 暴露原始异常内容，管理员在本地 failed 状态排查。

## 6. 不通过 M3 也能手动选择

交互式选择共享目录文件：

```powershell
python -m m1.run --workspace .\shared-workspace --select
```

直接指定 incoming 中的文件名：

```powershell
python -m m1.run --workspace .\shared-workspace --file web_alerts.xlsx
```

原命令 `--manifest ...` 仍兼容；三种入口互斥。--file/--select 同样不创建任务 Manifest，但 CLI 不提供 API 的持久队列和输入快照，运行期间不要改写输入。

## 7. 联调验收

```powershell
python -m unittest tests.test_api tests.test_handoff
```

测试使用隔离 CSV/Parquet、关闭真实 LLM 和在线情报，验证认证、列表、异步成功、幂等冲突、队列上限、输入变更、路径限制、失败状态、共享产物及无需 Manifest。实际工作区 API 配置仍可能启用模型，联调前由服务管理员决定是否启用。

运行时增加 `m1/api/tasks.sqlite3`、`m1/api/inputs/<task_id>/<原文件名>` 和服务锁。输入快照保留用于审计，不自动清理；不要在排队或运行期间删除。快照中的 source_file 会指向内部快照相对路径，原始上传文件名在任务 file.name 中。

本次完整回归共 50 项通过，包括 CLI 直接选文件及服务重启后的中断任务状态；测试未调用真实 LLM。内置页面的 DOM 操作使用 textContent 展示文件名和返回数据，未进行浏览器自动化视觉验收。

本交付尚未与独立 M3 应用进行端到端联调；没有 M3 代码、部署地址或接收渠道。M3 开发者可依以上已实现契约接入，取得原架构文档后再核对命名与消息约定。
