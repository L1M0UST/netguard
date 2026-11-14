# M1 白名单、检测规则与公开情报

## 白名单

运行配置支持 `whitelist_ips`（精确源 IP）、`whitelist_networks`（源 IP CIDR）和既有 `trusted_networks`。CIDR 采用标准 IPv4/IPv6 表达式，例如 `198.51.100.0/24` 或 `2001:db8:1234::/48`。这些网段只应在组织确认为可信、且确需降低噪声时添加；默认保持为空，避免把整个内网或共享出口静默排除。每次变更应记录所有者、用途、审批人和复核日期。

## M1 检测覆盖

M1 使用 11 类可解释规则：SQL 注入、XSS、路径遍历、命令注入、扫描器特征、Java 反序列化、文件包含、危险文件上传、CSRF、流量扫描/多路径扫描关联、提示注入。匹配证据会随会话记录；规则命中不是最终告警结论，最终等级仍由上下文风险分与后续关联研判决定。

## IOC 数据源

- Spamhaus DROP IPv4/IPv6：公开网络信誉列表。
- OpenPhish Community：公开钓鱼 URL feed。
- AlienVault OTX 订阅脉冲：通过 `.env` 的 `OTX_KEY` 获取；每次同步最多处理 25 个 pulse，结果在本地 SQLite 保留 72 小时。
- AbuseIPDB：按需查询 IP（在线来源，不加入本地批量 IOC 快照），响应缓存 15 分钟。

运行 `python -m m1.local_ioc --workspace workspace` 手动更新 feed。源失败会保留上一次成功快照；同步结果写入 `workspace/m1/local_ioc/update_status.json`。默认不在每次任务启动时下载，避免重复流量和服务限额消耗。

## 公共知识库

`data/threat_intel_public/` 包含通过 `scripts/update_public_intel.py` 更新的 CISA KEV 与 MITRE ATT&CK Enterprise 摘要。更新前确认网络可达；线上/模型数据源的可用性和条款会变化，应按需复核。免费模型可能收集提示词用于服务改进，故只应发送已脱敏且必要的摘要，不发送整份原始日志。
