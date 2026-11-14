# 全功能展示测试数据套件 · 使用说明

> 由 `scripts/build_test_suite.py` 按平台真实评分规则生成（2026-09-23 全部实测验证通过）。

## 评分标准（代码依据，造数按此精确设计）

| 规则 | 分值 | | 加分项 | 分值 |
|---|---|---|---|---|
| 远程命令执行 / Java反序列化 | 90 | | 会话内规则命中 ≥3 成员 | +10 |
| SQL注入 | 85 | | 会话内规则命中 ≥10 成员 | +20 |
| IOC 命中（Spamhaus/OpenPhish） | 80 | | 源活跃度（300s 内同源 ≥10 会话） | +10 |
| 目录遍历 / 文件包含 | 75 | | 关键资产（10.0.0.12/13） | +18/+16 |
| 文件上传 | 70 | | | |
| XSS | 65 | | M1 等级 | high ≥75 / medium ≥45 |
| CSRF | 60 | | M2 严重度阈值 | critical ≥85 / high ≥70 / medium ≥45 / low ≥20 |
| 端口扫描（flow_scan） | 55 | | 最终告警等级 | **max(M2 评分, M1 初筛)** |
| 提示注入探测 | 50 | | | |
| 扫描探测 | 45 | | | |

## 文件清单 → 演示功能 → 预期观察点

### 01_main_10k.csv（万级主数据集，10,200 行，官方 8 列格式 + ground truth）

| 场景 | 预期观察点（实测值） |
|---|---|
| 正常流量 ~9,200 行 | 降噪基线；原始 10,200 → 规范化 9,830 |
| 完全重复行 250 对 | M1 计数器 `filtered_duplicate=250` |
| 白名单源 192.0.2.100 × 120 行 | `filtered_whitelist=120`（白名单降噪） |
| 8 类攻击各 30 行 × 6 攻击源 | 8 类中文标签告警全检出，多画像 |
| 多路径扫描 10 轮 | `multi_path_scan` 规则（45 分 medium） |
| 源活跃度：同源 12 会话/300s 打 12 资产 | `score_components.source_activity=+10` |
| 会话频率：同会话 12 成员 | `score_components.session_frequency=+20` |
| Spamhaus IOC 命中（1.10.16.x 网段展开 IP） | `ioc_match=80` 分 high + M2 IOC 因子 |
| 钓鱼域名（OpenPhish 真实条目 awemissome.sbs 等） | M2 域名情报富化；情报查询可查 |
| 提示注入载荷 25 行 | `prompt_injection` 规则告警；智能模式时 `injection_blocked>0` |
| **CRITICAL 组合拳** 6 轮（Spamhaus IOC+多阶段+关键资产 10.0.0.12） | 最终等级 **critical**（M2 8因子≥85） |
| 多阶段跨会话攻击链 3 组 | M2 关联 multistage 链（最长 7 阶段） |

### 02_same_scenarios.xlsx
多模态对照：与 01 同场景的 XLSX 形态（验证 XLSX 解析链路）。

### 03_events.jsonl
多模态 JSONL：含 **8 条无意义行**（缺网络身份且无内容 → 演示丢弃 `filtered_meaningless=8`）。
（不含注入载荷行——明文注入串在 JSONL 中会被杀毒判定为脚本威胁；注入自防演示用 01。）

### 04_events.json
多模态 JSON 数组：含 **20 组完全重复对**（演示 JSON 输入的去重）。

### 05_attack_scenarios.pcap / 06_attack_scenarios.pcapng
PCAP 双格式（同一流量剧本，验证两种 PCAP 解析）：
- 端口扫描 45 端口 → `PORT_SWEEP` → `flow_scan` 规则 → 攻击链 **T1595 Active Scanning**（low）
- C2 心跳 8×30s + 正常流 + DNS（正常流被降噪正确丢弃）
- 证据摘要展示 **GLYPH 流文本**（多模态统一通道，PCAP-LM/PacketGlyph 思路）

### 07_main_wan.pcap / 08_main_wan.pcapng（万级 PCAP，11,414 包，双格式）
完整流量剧本：正常办公流 950 条×8-12 包 + DNS 300 + **定向端口扫描 8 源×45 端口（PORT_SWEEP）** +
分布式低频扫描 100 源 + **C2 心跳 6×30 次** + 数据外传 20 大流 + **Spamhaus IOC 攻击源 20 个打关键资产**。
实测：11,414 包 → GLYPH 聚合 **1,635 流**（包→流 7:1 降噪）→ 9 可疑会话 → 9 告警
（**IOC 源扫描=medium、普通扫描=low——评分层次分明**）→ DeepSeek 研判 9/9 成功。

### 09_main_wan.jsonl（万级 JSONL，10,042 行）+ 10_main_wan.xlsx（万级 XLSX，10,030 行）
完整场景集（网段 10.252 / 10.253 隔离）：正常流量 + 8 类攻击 + 扫描 + IOC + 钓鱼域名 + 提示注入 + 重复对。
JSONL 实测：54 告警（critical 1/high 1/medium 26/low 26——四档全命中）；
XLSX 实测：7 条 M2 合并大链（同源同目标会话被关联引擎合并属正常行为）。

### intel_query_targets.txt —— 威胁情报查询演示素材（前端 🔍 按钮）
Spamhaus 展开 IP（境外+恶意命中）/ 8.8.8.8（境外未命中）/ 10.60.33.18（内网）/
OpenPhish 钓鱼域名（恶意命中）/ 攻击类型知识卡（T1190+特征+处置）

## 实测汇总（2026-09-23，极速模式）

| 数据集 | 原始 | 可疑会话 | 告警 | 等级分布 | 多阶段链 | 画像 |
|---|---|---|---|---|---|---|
| 01_main_10k.csv | 10,200 | 72 | 55 | critical 1 / high 1 / medium 27 / low 26 | 30 条（最长 7 阶段） | 55 |
| 07_main_wan.pcap | 11,414 包 | 1,635 流→9 | 9 | medium（IOC源）/ low（普通扫描） | — | 9 |
| 09_main_wan.jsonl | 10,042 | — | 54 | critical 1 / high 1 / medium 26 / low 26 | — | 54 |
| 10_main_wan.xlsx | 10,030 | 284 | 7（合并大链） | medium 6 / low 1 | 6 | — |
| 05_attack_scenarios.pcap | 76 包 | 1 | 1 | low（T1595 扫描链） | — | 1 |
| 03_events.jsonl | 377 | — | — | 丢弃 8 条无意义行 | — | — |

**四档告警等级在主数据集中全部出现**——评分体系各档位均有数据触发。

## 使用方式

- **前端**：↺ 重置演示 → ＋新建分析任务 → 上传任一文件（多个文件分别建任务可对比多模态）
- **命令行**：`.venv\Scripts\python.exe -m orchestrator.driver run-file --file <文件路径>`
- **智能模式**：`.env` 里 `DEEPSEEK_ENABLED=1`（需 DeepSeek 余额）+ 本地模型 `start_all.bat`；级联第一档（cqsec）全免费
- 智能问答演示：完成后点"查询分析结果"→ 问"本任务告警总数多少？高危多少条？"（统计直答）/"SQL注入攻击怎么修复？"（本地模型）

## ⚠️ 杀毒软件提示

数据集与运行产物含**真实攻击载荷样本**（测试所需），Windows Defender 可能隔离个别文件
（已实测：明文 JSONL/JSON 证据文件会被隔离；平台证据已改为 Parquet 格式规避）。
若测试数据被隔离，请将目录加入白名单（管理员 PowerShell）：

```powershell
Add-MpPreference -ExclusionPath "E:\platform_taishi\taishi_platform\tests_integration\fixtures\suite"
Add-MpPreference -ExclusionPath "E:\platform_taishi\taishi_platform\workspace"
```

## 重新生成

```powershell
.venv\Scripts\python.exe scripts\build_test_suite.py
```
（确定性种子，重新生成的数据与本次完全一致）
