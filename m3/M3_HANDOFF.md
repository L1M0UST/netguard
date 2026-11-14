# M3 独立交付与联调说明

依据：语雀《网络攻击智能研判系统——详细架构与并行开发文档 v2.0》的 M3 展示与交互、文件交换、证据约束和安全要求。对应页面：
https://www.yuque.com/u55808888/xk92z5/ngpct52ugouatq3o

## 当前边界

M3 创建任务和文件清单，仅通过共享文件接收 M1/M2 状态与结果；不调用其 HTTP/RPC/Redis，不替代降噪、检测、ATT&CK 映射、攻击链构建或画像算法。浏览器调用 M3 的 HTTP/SSE 是允许的。

**下面的字段是本仓库实现的可运行对接草案，不是已获团队确认的正式协议。** M1/M2 可以按它实现，也可以提供正式 schema 后只修改 M3 文件适配器。语雀“接口文档”的模型调用示例不等于模块之间的文件协议。

## 已实现

|文档流程|实现位置与行为|
|---|---|
|上传 → 任务 → 状态|server.py、workspace_io.py；大小/格式头校验、SHA256、STAGING 原子发布 READY、模块状态聚合、SSE 重连与任务恢复|
|概览|M1/M2 统计、链/画像数量、Top IOC、耗时；缺失显示“未提供”；全任务类型分布与等级饼图并排；按用户要求删除告警趋势|
|告警 → 详情|等级、关键字（战术/技术/攻击者/受害者）、时间、置信度筛选；50 条分页；风险理由/攻击链/证据原始引用/漏洞/建议来源|
|攻击链|按 stages 与 edges 绘图，保留分支和方向；节点证据详情、缩放复位；不推断不存在的阶段或关系|
|画像|实体、IOC、受害资产、链引用、证据引用及提供的关系；不补造事实|
|助手|任务范围的证据 → 告警 → 本地知识检索；统计查询快捷入口、引用、流式回答和持久历史；没有匹配证据明确说明|
|报告|完成后才允许 JSON/PDF 导出；含版本、降级标记、建议及证据|
|已读/审计|任务+告警复合键保存已读；刷新与重启恢复；查看告警、问答、导出操作记录；任务内可查最近 100 条|
|原始数据|M3 自有上传副本默认 72 小时后清理，仅终态任务；等待中的任务保留，用户原文件不动；已有无上传时间元数据的旧副本不自动清理|

## 文件协议草案

根路径由 `NETGUARD_WORKSPACE` 指定，默认 `shared_workspace`。

1. M3 写 `m3/STAGING/<task_id>/` 下各上传副本和 manifest.json，flush/fsync 后将整个目录改名到 `m3/READY/<task_id>/`。
2. M1 认领后可以将输入目录改名到自身约定的 PROCESSING/DONE。M3 不修改 M1/M2 的处理中目录。M1 → M2 中间产物由这两个模块约定，M3 不消费它。
3. M1/M2 各写 `m1|m2/STATUS/<task_id>/status.json`，先写临时文件再原子替换。
4. M2 写 `m2/STAGING/<task_id>/{bundle.json,manifest.json}`，完成并计算校验和后将目录原子改名到 `m2/READY/<task_id>/`。READY 是完整不可变发布结果；不要在那里边写边读。
5. M3 只在 bundle 校验通过后标为完成。COMPLETED 状态文件本身不足以让任务完成。失败重试生成新任务 ID；不覆盖先前的证据记录。

### TaskManifest.v1

`schema_version`, `task_id`, `created_at`, `source_files`, `user_prompt`, `versions`。
每个 source_file：`file_id`, `filename`, `size`, `sha256`, `path`（相对任务目录的文件 ID）。文件复制不保留扩展名，M1 应以 filename 判断原格式。

### Status.v1

```json
{"schema_version":"Status.v1","task_id":"TASK_ID","state":"RUNNING","progress":40,"message":"M1 降噪中"}
```

state 为 QUEUED/RUNNING/COMPLETED/FAILED/DEGRADED，progress 在 0–100 之间。状态等待/失败不能伪装成有效检测结果。

### ResultManifest.v1

```json
{"schema_version":"ResultManifest.v1","task_id":"TASK_ID","sha256":"bundle.json 原始字节的 SHA256"}
```

### AttackChainBundle.v1

完整可运行样例在 `demo_bundle.py`，机器可读基础 schema 见 `schemas/AttackChainBundle.v1.json`；引用完整性等跨对象约束由 `Bundle.validate_references` 追加检查。

- 必填：schema_version、task_id、alerts、chains、evidence、versions。
- versions 必须包含非空 rule_version/model_version/prompt_version/code_commit/threshold_version。不适用时写 `disabled` 等明确值，不能省略。M3 不能代替生产者证明版本真实性。
- alerts：唯一 alert_id、title、severity、非空 event_ids；severity 是 critical/high/medium/low/info。可提供 source、target、timestamp（带时区 ISO8601）、tactic、technique、attack_type、0–1 confidence、risk_reason、vulnerabilities、recommended_actions。
- evidence：唯一 event_id，建议提供 summary/source/target/timestamp/raw_ref。raw_ref 应含文件 ID、行号或包号；M3 显示引用，不执行路径中的内容。
- chains：唯一 chain_id、severity、stages、edges；stage 有唯一 stage_id、tactic、technique、evidence_event_ids、confidence、两个 ISO8601 时间组成的 time_range。edges 是 `[起始 stage_id, 目标 stage_id]` 数组。
- profiles：ip/domains/urls/hashes/victims/active_time/attack_types/ioc_hits/chain_ids，以及必填非空 evidence_refs。可选 relationships 每条也必须有 evidence_refs。
- metrics：raw_count、denoised_count、suspicious_count、duration_seconds、可选 top_iocs。M3 不从演示数字推断这些指标。
- report：summary、可选 vulnerabilities、recommended_actions；每条建议的 source 为 rule_based/knowledge_base/llm_generated/analyst_verified，text 为具体建议。
- degraded：是否降级。附加字段会保留。所有事件/阶段/链引用都必须可解析，否则整包拒绝。

## 数据与运行配置

用户提供的 XLSX 有 11,000 条样例，最后一列 `attack_type(结果列，需参赛选手判断输出)` 是评测标签，不能作为检测答案泄漏给模型。M3 目前原样投递 XLSX，M1 需支持解析并排除标签列；CSV/JSON/PCAP 同样由 M1 解析。上传成功不等于分析成功。

`.env.example` 是环境变量清单，服务不会自动加载它；在启动终端设置需要的变量。LLM 默认禁用。本地检索可独立运行，但不等于通过真实模型验收；启用模型要配置 ENABLED=1、BASE_URL（以 /v1 结尾）、MODEL 及需要的 API_KEY。模型调用只用于 M3 问答，故障和无效引用会降级。3 条本地 ATT&CK 知识仅是基础知识库，团队可补充可信漏洞/修复来源。

敏感字段和邮箱在展示/问答上下文中脱敏，这不是通用 DLP。原始文件只存本地共享目录。72 小时清理覆盖 M3 自有副本；M1/M2 的 PROCESSING、中间产物和结果保留由各生产者负责。

默认只监听 127.0.0.1。审计 actor 来自 `NETGUARD_ACTOR`（默认 local-user），用于当前单用户桌面模式；多人部署必须先接入实际身份认证和访问控制，不能将这个环境变量当作可信登录身份。

## 启动与验收

```powershell
E:\python\python.exe -m uvicorn server:app --host 127.0.0.1 --port 8001
E:\python\python.exe -m unittest test_workspace test_m3_acceptance -v
node --check workflow.js
node --check m3-ui.js
```

也可双击 `启动网站.cmd`，保持终端运行。页面 http://127.0.0.1:8001/，健康检查 /health，API 文档 /docs。

独立验收在临时目录和随机端口运行，不写入真实工作区；已通过 7 项测试，覆盖等待、发布、证据引用、校验失败、上传拒绝、检索降级、已读/历史持久化、重启、报告及 TTL。`test_contracts.py` 是旧显示契约样例，不代表文件协议的团队确认。旧 `test_flow.py` 会写演示任务到正在运行的服务，正式数据环境不要拿它做无污染验收。

## 还要等团队的事项

1. M1/M2 确认文件 schema、版本字段和共享路径，并按协议提供真实状态/结果（或给出需调整的正式 schema）。
2. M1 解析用户样例、排除标签列并输出真实事件；M2 输出有证据的分级、链、画像、漏洞及建议。
3. 全链路验收真实数据、时序、失败/恢复、大批量结果和版本一致性。当前演示记录不能证明检测质量。
4. 若比赛要求真实 LLM，提供可用模型配置并做真实问答验收；如果要多人部署，还需身份系统。这两项不是等待 M1/M2 就会自动解决的条件。
