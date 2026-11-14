# 密钥与配置目录（secrets）

**这是整个发行包中唯一需要你手动填写文件的目录。**

## 为什么单独放一个目录

发行包在生成时已做脱敏处理：开发机上 `.env`、`workspace/m1/config.json` 中
出现过的真实 API Key **全部未被打包**。为了让你后续只在这一个地方维护密钥，
所有需要人工填写的配置都集中在本目录。

## 目录内容

| 文件 | 作用 | 是否必须填写 |
|---|---|---|
| `.env.template` | 环境变量模板。**复制为 `.env` 后填写** | 不需要填（纯本地模式可直接用） |
| `m1_config.template.json` | M1 降噪管线的运行配置模板，密钥字段已留空 | 不需要改（默认 `local_only`） |
| `README-密钥填写说明.md` | 本文件 | — |

## 使用步骤

```powershell
# 在包根目录执行：复制模板为实际生效的 .env
Copy-Item secrets\.env.template secrets\.env
notepad secrets\.env          # 按需填写 Key；不填则纯本地运行
```

之后运行 `deploy\2_start_all.ps1`，启动脚本会自动把 `secrets\.env`
载入为 `taishi_platform\.env`。

## 两种运行模式

### 模式 A：纯本地（默认，推荐比赛现场）

`secrets\.env` 中保持 `DEEPSEEK_ENABLED=0`，**一个 Key 都不用填**。

- 本地微调模型 cqsec（Qwen3-4B QLoRA，包内自带权重）提供：告警研判、事件报告、
  攻击者画像、威胁情报问答、运营总结五大能力
- M1 规则引擎 + IOC 库 + M2 关联研判全链路本地完成
- 全程**不联网、不发请求、不消耗额度**，演示可控、无失败回退风险

### 模式 B：云端增强（可选）

把 `.env` 中 `DEEPSEEK_ENABLED` 改为 `1`，并填写以下任一 Key：

| Key | 用途 | 获取地址 |
|---|---|---|
| `DEEPSEEK_API_KEY` | M1/M2 云端研判增强 | https://platform.deepseek.com |
| `OPENCODE_API_KEY` | 云端链路第一档 | https://opencode.ai |
| `COMMANDCODE_API_KEY` | 云端链路第二档 | https://api.commandcode.ai |
| `OTX_KEY` | 在线威胁情报信誉 | https://otx.alienvault.com/api |
| `ABUSEIPDB_KEY` | IP 信誉查询 | https://www.abuseipdb.com/account/api |

填写后系统按 `OpenCode → Command Code → DeepSeek` 顺序尝试；任一路径失败会
自动回退到本地模型与规则引擎，**不会因为云端正不可用而导致系统不可用**。

`NETGUARD_INTEL_PROXY` 用于在线情报源的代理（例如 `http://127.0.0.1:7890`）；
比赛现场不联网时留空即可，对应在线源会被自动跳过。

## 安全提醒

- `secrets\.env` 一旦填写了真实 Key，**不要**把它提交到公开仓库、
  不要放进答辩 PPT / 录屏 / 截图中
- 如果这个包需要交给别人，重新走一遍脱敏即可：
  删掉 `secrets\.env`（只留 `.env.template`）、确认 `taishi_platform\.env`
  与 `taishi_platform\workspace\m1\config.json` 中没有残留 Key
- 开发机上的原始密钥位置（供核对）：
  `taishi_platform\.env`、`taishi_platform\workspace\m1\config.json`
  ——这两个文件在发行包中均已重置为不含密钥的状态
