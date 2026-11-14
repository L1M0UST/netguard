# NetGuard M3 流程联调版

最新验收、字段草案和外部依赖见 [M3_HANDOFF.md](M3_HANDOFF.md)。当前文件 schema 尚需 M1/M2 团队确认，演示数据不代表真实检测。

接口与验收资料：[接口文档](docs/API.md) · [测试用例与执行记录](docs/TEST_CASES.md)。包含 HTTP/SSE、共享文件协议、异常与边界场景，以及现有隔离测试的实际覆盖范围。

## 启动

```powershell
python -m pip install -r requirements.txt
python -m uvicorn server:app --host 127.0.0.1 --port 8001
```

打开 http://127.0.0.1:8001 。不要再使用 8000 的静态文件服务，静态服务器无法处理 API。

## 按流程图验收

1. 点击新建任务，选择非空 CSV/XLSX/PCAP/JSON，提交分析备注。
2. 前端调用 POST /api/v1/files，文件流式写入本机 data，计算 SHA256。
3. 调用 POST /api/v1/tasks，返回 task_id。
4. EventSource 订阅 GET /api/v1/tasks/{task_id}/stream，实时更新阶段和百分比；中断自动重连。
5. 完成后读取任务、告警、攻击链，渲染节点和证据关联；支持告警等级过滤。
6. 点击向助手提问，调用 POST /api/v1/chat，逐段渲染 delta，随后显示 evidence；错误可见。
7. 点击导出 JSON/PDF，从报告接口下载实际文件。任务完成前禁用提问和导出。

运行 `python -m unittest test_workspace test_m3_acceptance -v` 独立检查接口流程，测试使用临时目录和随机端口。
OpenAPI：/openapi.json；接口文档：/docs。

## v2.0 架构边界

M3 是唯一面对浏览器的模块。它创建 `TaskManifest.v1` 并投递到
`shared_workspace/m3/READY/<task_id>`，然后只读取 M1/M2 的
`Status.v1`、`ResultManifest.v1` 和 `AttackChainBundle.v1` 文件；M3 不调用
M1/M2 的 HTTP、RPC、gRPC 或 Redis 接口，也不实现检测和攻击链算法。

结果目录通过临时目录写入后原子改名，bundle 使用 SHA256 校验。服务会校验
`schema_version`、版本信息、证据事件引用、攻击链 stage/edge 和报告建议来源，
校验失败的结果不会进入页面。SQLite 仅保存 M3 的任务索引和审计记录，原始文件
保留在 `data`，共享结果保留在 `shared_workspace`。

当前前端沿用现有 HTML/CSS/JS 页面。M1/M2 按当前文件草案写入即可独立联调；正式协议如有不同，需要调整文件适配器。LLM 未启用时，助手使用 bundle 中的证据检索降级回答。

## 本轮交互优化

- SQLite 保存文件元信息和任务；服务重启后恢复等待并重新读取文件状态，失败任务可重试。
- 浏览器刷新恢复选中任务和 SSE 订阅；可切换历史任务。
- 首页展示服务任务计数，移除写死趋势图，不再显示虚构准确率。
- 攻击链支持缩放、复位、点击节点查看证据。
- 原有接口流程测试与新进程加载持久任务检查通过。

## M1/M2 交接清单

- M1/M2 写入 `Status.v1`，状态为 `QUEUED/RUNNING/COMPLETED/FAILED/DEGRADED`。
- M2 在 `m2/READY/<task_id>` 写入 `bundle.json` 和带 SHA256 的 `ResultManifest.v1`。
- 每个告警带 `event_ids`；每个攻击链 stage 带 `evidence_event_ids`，且引用 bundle 的 evidence。
- 保留 rule/model/prompt/code/threshold 版本信息，报告建议必须标明来源。
- M3 会自动刷新状态、展示画像/运营总结/攻击链证据、提供审计和 JSON/PDF 导出。
