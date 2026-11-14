# SuspiciousEventBatch 2.0：M1 → M2 契约

复核分组更新：similarity_version=payload-simhash-v1。规则/路径/IOC 候选范围内增加载荷摘要与近似特征校验，review_group_id 可能随新批次改变，不作为跨运行告警唯一键。L3 优先覆盖载荷复核组。内部特征不写入产物，近似分组仍不确认同一攻击者或同一恶意结论；M2 按成员 session_id 回查。历史不含 similarity_version 的分组是较粗的路径/规则分组。

新增可选 artifact `review_groups` 与会话可空字段 `review_group_id`。该分组按规则、服务方法、路径模板及 IOC 模式组织人工复核，可跨来源/资产/时间，`correlation_status=review_pattern_only`，不是攻击链或确认的安全事件。包含 representative_session_id、related_session_ids、session_count、event_count、source_count、target_count。每个可疑会话恰好属于一个复核组；M2 保留原会话消费语义，不能把代表会话的 LLM 结论传播给全组。`status.quality` 区分展示压缩、L3 覆盖与待人工标注的准确率。

L2 规则 1.3：新增 `multi_path_scan` 行为命中，evidence 增加可选整数 `window_seconds`、`min_unique_paths`、`min_sensitive_paths`（检测配置阈值，不是精确统计值）。`attack_campaigns` 新增 `correlation_status=candidate` 和 `source_identity_shared`，采用资产/服务/域名/攻击类别约束，不代表确认的攻击者或跨资产攻击链。M2 需接受更细的候选分组并自行做跨资产关联。`activity_groups` 可通过不同路径重复引用同一会话，消费时按 session_id 去重；基础会话不重复删除。时间窗是首事件锚定的有界跨度，非自然日分桶。详情、会话、候选文件仍遵循原有原子发布和引用规则。

本地 IOC 增强：`ioc_matches` 中 `type` 可为 `cidr`，此时 `value` 为网段，实际命中的地址由 `matched_field` 指向会话的 `src_ip` 或 `dst_ip`。新增可选字符串字段 `fetched_at`、`expires_at`（UTC ISO 8601），分别表示本地下载时间与缓存到期时间，不能解释为攻击发生时间。手工 IOC 等其他来源可以没有这些字段或为 null。M2 读取 Parquet Struct 时应兼容这些可选字段。

新增可选 artifact `activity_groups`：多特征相似活动候选，包含 activity_id、route_template、related_session_ids、first_seen/last_seen、source_identity_shared、correlation_status=candidate 等字段。M2 可忽略未知可选文件，或据此进一步验证；基础 suspicious_events 不因这些分组而删除。`status.l3_status` 汇总最终候选处理结果；`llm_attempts/llm_retries` 区分实际请求次数与候选数量，重试不增加候选比例。

批次是标准化可疑会话和证据引用集合，不是 ZIP。主输入为 suspicious_events；event_details 按 related_event_ids 回查全部成员；semantic_judgements 可选，按 session_id 联接；attack_campaigns 仅作初步线索；all_sessions 用于审计。

## 发布和幂等

新输出路径：`shared-workspace/m1/ready/<batch_id>/<run_id>/`。batch_id 为逻辑批次名，run_id 为每次运行的唯一标识。旧输出不覆盖，运行命令打印实际目录。先写 `m1/staging/<run_id>/`，关闭文件、校验行数及 SHA-256 后，以同文件系统目录 rename 发布。失败文件留在 staging，不供 M2 消费。

M2 仅扫描 ready 内包含 READY.json 的运行目录。READY 的 batch_sha256 校验 batch.json；contract_version 必须为 2.0，status.stage 必须为 READY。artifact_metadata 包含相对路径、格式、行数、字节数、SHA-256、布局版本。校验失败拒绝读取，只读取 artifacts 清单里的文件。发布后不可原地修改。

consumption_key 为 batch_id:run_id。M2 应在自己的事务存储中持久化消费记录，处理完成才确认。重跑是新投递，跨运行告警去重应结合 session_fingerprint、时间和资产。M1 不提供 M2 的消费确认/事务或 exactly-once 保证。

## 会话字段

| 字段 | 类型与约定 |
|---|---|
| batch_id/session_id/event_id | 字符串关联标识；event_id 重跑可变化 |
| related_event_ids | 所有成员 ID 列表，查询 event_details |
| first_seen/last_seen | 可空 ISO 8601 时区时间字符串 |
| src_ip/dst_ip/protocol/src_port/dst_port | 观测字段，缺失可为空，不自动确认攻击者身份 |
| victim_asset_id | 可空字符串，由 asset_ids 按目标 IP 映射；受害角色仍需 M2 判断 |
| asset_identity_source | configured 或 unknown |
| source_role/direction | 当前 unconfirmed/unknown |
| source_identity_shared | 来源命中 shared_egress_ips 为 true；false 不证明是独占出口 |
| session_fingerprint | 排序后成员内容指纹的 SHA-256，不含时间；缺失指纹退化为事件 ID |
| fingerprint_version | session-content-v1，不是独立唯一事件键 |
| domains/paths | 去重排序样本，各最多 50 项 |
| domains_count/paths_count | 完整去重数量，超过列表长度表示截断 |
| ioc_matches | List<Struct<type,value,matched_field,source>> |
| tactic_candidates | 字符串列表，当前为空，M2 负责最终 ATT&CK 映射 |
| event_count/rule_hits/evidence | 聚合条数、规则标签及依据 |
| risk_score/risk_level/score_components | M1 初筛优先级，非攻击概率 |
| semantic_status | disabled/not_selected/completed/failed/skipped_failure_limit |

IOC 来源 configured 表示手工配置的本地集合，无自动有效期；threatbook 为在线微步。本地 SQLite 指标保留具体来源和缓存有效期。M2 继续增强时效和信誉。所有关联字段应加权使用，不要求全部完全一致。相同内容在不同时间可能有相同指纹。

semantic_status=completed 表示有合法模型响应，非结论正确性的保证；failed 为请求或校验失败；skipped_failure_limit 为失败阈值后未提交；disabled 包括未启用或配置不可用。status.semantic_counts 是可疑会话状态汇总。模型置信度未经校准，处置建议只输出，不执行封禁。

Parquet 原生 List/Struct 无需 json.loads；显式 JSONL 兼容输出语义一致。JSON 控制文件为 UTF-8。空值是未知，不应因两边都是 null 而增加关联权重。无时区源时间仍按运行机器时区解释，部署必须固定时区。批次 time_range 是可疑会话范围，全空时为 null。

## 配置与 M2 示例

在 config.json 顶层填写实际资产和共享出口信息（目前默认空）：

```json
"asset_ids": {"10.0.0.2": "asset-payment-01"},
"shared_egress_ips": ["10.0.0.1"]
```

```python
from pathlib import Path
from m1.handoff import read_batch, iter_suspicious

directory = Path('shared-workspace/m1/ready/batch-excel-001/<run_id>')
batch = read_batch(directory)
key = batch['consumption_key']  # M2 检查/持久化去重记录
for session in iter_suspicious(directory, batch_size=1000):
    print(session['session_id'], session['first_seen'], session['ioc_matches'])
```

read_batch 检查发布标记、版本、行数及校验和；iter_suspicious 分批读取。外部 M2 可依契约自行实现，不要求复用内部处理代码。旧版直接放在 batch_id 目录下的输出不满足本契约，重新运行生成新版。
