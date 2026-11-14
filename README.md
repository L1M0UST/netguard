# taishi_platform —— 网络安全态势智能感知平台

> 赛题2：网络安全态势智能感知（2026年第二届重庆市AI大模型创新应用大赛）
> 由三位成员的后端（M1 降噪 / M2 研判）、前端交互层（M3 BFF）整合而成的统一项目。

## 一、整体架构

```
浏览器前端 (index.html + app.js)
      │ 同源 /api/v1/*
      ▼
M3 BFF (m3/server.py, FastAPI :8001)          ← 前端成员交付，含全部 16 个接口与 SSE
      │ ①上传文件写入 workspace/m3/READY/<task>/
      │ ②轮询 workspace/m1|m2/STATUS/<task>/status.json (Status.v1)
      │ ③读取 workspace/m2/READY/<task>/bundle.json (AttackChainBundle.v1)
      ▼
编排器 (orchestrator/driver.py, watch)
      │ 1. 投递输入到 workspace/incoming/
      │ 2. python -m m1.run                       → M1 降噪管线
      │ 3. bridge.export_batch                    → 契约转换（见下）
      │ 4. python -m backend.module2_chain.main   → M2 关联研判管线
      │ 5. bundle.assemble                        → 组装 M3 结果包
      ▼
M1 (m1/)  多格式接入→Schema映射→去重/白名单→L1规则+IOC→L2会话→L3 LLM研判
      ↓ suspicious_events.parquet (会话级, batch.json 契约 2.0)
bridge (bridge/)  ★新增★ 会话→事件展开 + 字段映射 + 官方中文标签层 + 真实IOC导出
      ↓ batch_000001.parquet + manifest.json (SuspiciousEventBatch.v1 契约 1.0.0)
M2 (backend/module2_chain/)  关联引擎→威胁情报→ATT&CK→LLM(DeepSeek)→反幻觉校验
      → 攻击链/画像/威胁要素/风险报告 (workspace/m2_output/<task>/)
      ↓
bundle (bundle/)  ★新增★ M2 五类 JSON → AttackChainBundle.v1（引用闭合自校验）
      ↓
llm (llm/cqsec.py)  ★新增★ 本地垂域模型五大能力：智能问答/运营总结/画像增强
```

### 为什么要 bridge（矛盾点 #1/#8 的解决）

M1 产物是**会话级**（1 行 = 1 会话，含 `related_event_ids`），且没有 M2 必填的
`event.task_id` / `event.timestamp` 列——直连会被 M2 静默丢弃全部行。
bridge 按 `related_event_ids` 把可疑会话**展开回事件级**（保留时间戳供 M2 时间衰减
关联），会话级检测结论复制到成员事件，`session_id` 原样传递（M2 同会话关联 +0.10 加分）。
不把多个会话合并成一个事件：那会破坏时间窗关联且证据无法指向真实事件。

### 官方中文标签层（矛盾点 #5）

`bridge/labels.py` 把 M1 规则名确定性映射为赛题官方标签（`path_traversal`→`目录遍历攻击`…），
随事件/告警输出 `attack_type` 字段；无规则命中标 `待研判`，绝不使用数据集 ground-truth 列。

## 二、目录结构

```
taishi_platform/
├── m1/                       # 成员A后端：告警接入+智能降噪（原 he-l，未改核心）
├── backend/                  # 成员B后端：攻击关联+智能研判引擎（原 NetworkAttackAnalysisSystem）
│   ├── common/schemas/       #   公共数据契约
│   └── module2_chain/        #   M2 管线（含 201 个测试）
├── m3/                       # 成员C前端+BFF（原 taishi_web，仅问答接入 cqsec 微调）
├── bridge/                   # ★ M1→M2 契约转换 + 标签映射 + IOC 导出
├── bundle/                   # ★ M2 输出 → M3 AttackChainBundle.v1 组装器
├── orchestrator/             # ★ 流水线编排器（watch / run-file）
├── llm/                      # ★ 本地垂域模型 cqsec 五大能力客户端
├── config.yaml               # M2 引擎配置（已对齐统一工作区）
├── .env / .env.example       # 统一密钥与模型配置
├── workspace/                # 运行时工作区（incoming / m1 / m2_inbox / m2_output / m3 / bridge）
├── data/threat_intel/        # 真实威胁情报（M1 IOC 库导出，供 M2 使用）
├── tests_m1/                 # M1 原有测试（56 项）
├── tests_integration/        # ★ 整合层测试
├── docs_m1/ · m3/docs/       # 各模块原始文档
├── docs/                     # 整合文档（架构/映射表/部署）
└── scripts/                  # start_all.bat / update_ioc.bat / 测试脚本
```

## 三、快速开始

比赛前的统一启动、离线复现评测、样本许可与 PCAP 能力边界见：
`docs/赛前验证与复现说明.md`、`docs/数据来源与PCAP边界.md`。历史 UI 清单见 `docs/验收测试指南.md`，其中旧耗时和样例数字不作为当前实测结论。

```powershell
# 0) 环境（Python 3.11+）
D:\python3.11\python.exe -m venv .venv
.venv\Scripts\pip install pyarrow openpyxl polars "pydantic>=2" orjson PyYAML httpx fastapi "uvicorn[standard]" python-multipart reportlab python-dotenv

# 1) 配置 .env（DeepSeek key、cqsec 地址；模板见 .env.example）

# 2) 更新真实威胁情报（可选，需外网；失败可跳过，M2 用兜底数据）
scripts\update_ioc.bat

# 3) 启动（两个窗口）
.venv\Scripts\python.exe -m uvicorn server:app --host 127.0.0.1 --port 8001   # cwd = m3/
.venv\Scripts\python.exe -m orchestrator.driver watch                          # cwd = 项目根

# 4) 浏览器打开 http://127.0.0.1:8001 上传文件、创建任务、看进度/报告/问答
#    本地模型服务（cqsec）按需启动：
E:\code\2026年第二届重庆市AI大模型创新应用大赛\start_all.bat
```

命令行直跑（不走前端，联调用）：

```powershell
.venv\Scripts\python.exe -m orchestrator.driver run-file --file path\to\赛题2.xlsx
```

## 四、模型分工

| 模型 | 用途 | 调用方 |
|---|---|---|
| DeepSeek `deepseek-flash`（云端，低成本推理档） | M1 L3 升级档（级联第二档）、M2 攻击链分析（Top-60 预算、`response_format: json_object`） | m1/run.py、module2_chain LLMInvoker |
| cqsec 本地微调 Qwen3-4B（127.0.0.1:8008） | ①单条告警研判（**L3 级联第一档**） ②事件报告 ③攻击者画像 ④**智能问答**（知识类） ⑤**运营总结** | llm/cqsec.py → M1 L3 / M3 /api/v1/chat、bundle 报告 |

## 五、创新点实现（对应 讨论2 的候选编号）

| 编号 | 创新点 | 位置 | 演示方式 |
|---|---|---|---|
| ① | 小-大模型级联路由（cqsec 先判→低置信升级 flash） | m1/run.py `cascade_local_judge`，统计在 `status.metrics.cascade` | M1 状态指标：local_hits/escalations |
| ② | 证据链置信度卡片（Grounded Confidence） | bundle `chains[].confidence_card` + 前端 `🛡` 按钮 | 8 因子条形图+反幻觉结论+惩罚项 |
| ③ | PCAP→Glyph 流摘要多模态 | m1/run.py `pcap_to_glyph_rows` + `flow_scan` 规则 | sample_traffic.pcap：端口扫描→T1595 链 |
| ⑤ | 一键自动调查 + SSE 轨迹 | M3 `/api/v1/tasks/{id}/investigate` + 前端 `⚡` 按钮 | 流式"载入→富化→逐链→反幻觉→结论" |
| ⑥ | 告警提示注入自防（LogInject 防护） | m1/run.py `sanitize_for_llm` + `prompt_injection` 规则 | injection_alerts.csv：载荷出网前被 `[注入内容已拦截]` |
| 扩展 | 威胁情报详情查询（离线） | M3 `/api/v1/intel/lookup` + `intel_lookup.py`（自实现 ip2region xdb 读取器） | 前端 `🔍`：境内/境外、IOC 命中、攻击类型知识卡 |
| 运维 | 演示重置 | M3 `POST /api/v1/admin/reset` + 前端 `↺` | 有任务运行时拒绝重置 |

## 六、当前状态与已知限制

- ✅ 端到端全链（xlsx/PCAP 上传 → 降噪 → 级联研判 → 报告/链/画像 → 前端展示/问答/调查/情报）已打通
- ✅ 测试：M2 200/201（唯一失败项为基线环境性）、M1+整合 72/72
- ✅ 全量 1.1 万条智能模式验证通过（详见 docs/数据处理全流程图.md 与 docs/验收测试指南.md）
- 🟡 PCAP 为元数据级 Glyph 通道（载荷重组列为后续工作）；问答知识类依赖本地 8008 在线，否则回退本地检索
- 🟡 垂域模型训练创新（级联研判头/数据飞轮）为备选，见 docs/模型训练创新指南.md
