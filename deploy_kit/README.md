# NetGuard 网络安全态势智能感知平台

> 赛题2：网络安全态势智能感知 · 2026 年第二届重庆市 AI 大模型创新应用大赛
> 最小可运行发行包 — 整包复制到任意 Windows 主机即可运行

**目标主机无需安装 Python、无需联网、无需任何 API Key。**

---

## 三步跑起来

在**发行包根目录**打开 PowerShell，依次执行：

```powershell
# 1) 环境自检（只读，不改动任何东西）
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\1_install_deps.ps1 -CheckOnly

# 2) 安装依赖（离线，约 1-2 分钟；已预建好 venv 时会自动跳过）
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\1_install_deps.ps1

# 3) 一键启动
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\2_start_all.ps1
```

看到 `启动完成` 后，浏览器打开：

### 👉 http://127.0.0.1:8001

停止服务：`powershell -NoProfile -ExecutionPolicy Bypass -File deploy\3_stop_all.ps1`

---

## 部署验证

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\4_smoke_test.ps1
```

四级验证：包完整性 → 服务在线 → 模型推理 → **全链路产出 bundle.json**。
全部通过即部署成功。

---

## 系统能力

| 模块 | 能力 |
|---|---|
| **M1 降噪** | 多格式接入（CSV/XLSX/JSON/JSONL/PCAP）→ Schema 映射 → 去重白名单 → L1 规则 + IOC → L2 会话 → L3 本地模型语义研判 |
| **bridge** | 会话级→事件级契约转换 + 赛题官方中文标签层 + 真实 IOC 导出 |
| **M2 研判** | 攻击关联引擎 → 威胁情报 → ATT&CK 映射 → 大模型研判 → 反幻觉校验 → 攻击链 / 画像 / 威胁要素 / 风险报告 |
| **M3 前端** | Web 界面 + 16 个 API + SSE 实时进度 + AI 问答 + 威胁情报查询 + PDF 报告导出 |
| **本地垂域模型** | Qwen3-4B QLoRA v3.2 微调，五大能力：告警研判 / 事件报告 / 攻击者画像 / 情报问答 / 运营总结 |

---

## 运行模式

| 模式 | 配置 | 联网 | 说明 |
|---|---|---|---|
| **纯本地**（默认，推荐赛场） | `DEEPSEEK_ENABLED=0` | 不需要 | 本地模型 + 规则引擎，功能完整、演示可控 |
| 云端增强 | `DEEPSEEK_ENABLED=1` + 填 Key | 需要 | 追加云端大模型研判质量；云端不可用时自动回退本地 |

切换方式：复制 `secrets\.env.template` 为 `secrets\.env` 后编辑。
**这是唯一需要手填配置的地方**，详见 `secrets\README-密钥填写说明.md`。

---

## 目录导航

| 目录 | 内容 |
|---|---|
| `taishi_platform\` | 项目源码（M1 / M2 / M3 / bridge / bundle / orchestrator / llm） |
| `model\` | 本地微调模型权重、llama.cpp 运行时、LoRA 适配器、训练与评测资料 |
| `runtime\python\` | 便携 CPython 3.11（目标主机免安装） |
| `deploy\` | 一键安装 / 启停 / 自检脚本 + 离线依赖 wheel |
| `secrets\` | ★ 密钥目录（唯一需要手填的地方） |
| `deliverables\` | ★ 交付材料占位（PPT / 文档 / 视频，待补充） |
| `logs\` | 运行日志 |

---

## 详细文档

| 文档 | 内容 |
|---|---|
| **`DEPLOY.md`** | **部署环境配置说明（主文档）**：环境要求、部署步骤、配置项、常见问题、安全合规 |
| `MANIFEST.txt` | 包清单与各部分体积、包含/排除说明 |
| `SHA256SUMS.txt` | 关键文件校验和 |
| `secrets\README-密钥填写说明.md` | 密钥填写与两种运行模式 |
| `taishi_platform\docs\` | 技术文档、验收测试指南、赛前验证与复现说明、数据来源与 PCAP 边界 |
| `model\api-references\` | cqsec 模型 API 对接文档与官方测试用例 |

---

## 常见问题速查

| 现象 | 处理 |
|---|---|
| 报「禁止运行脚本」 | 用 `powershell -NoProfile -ExecutionPolicy Bypass -File ...` 方式执行（见 `DEPLOY.md` §7.2 Q1） |
| 模型推理很慢 | 未启用 GPU；检查 `nvidia-smi` 与 `logs\model-8008.log`（见 Q2） |
| 任务一直「处理中」 | 看 `logs\orchestrator-console.log`；模型离线会自动降级，不会卡死（见 Q3） |
| 端口被占用 | `deploy\3_stop_all.ps1` 清理，或 `-WebPort 9001 -ModelPort 9008` 换端口（见 Q4） |
| 换目录后 venv 起不来 | 启动脚本会自动修正；必要时 `1_install_deps.ps1 -Force` 重建（见 Q5） |
| PDF 中文方块 | 改 `NETGUARD_PDF_FONT` 为目标机已有字体（见 Q7） |

完整排查见 `DEPLOY.md` 第七章。
