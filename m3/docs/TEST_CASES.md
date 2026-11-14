# NetGuard M3 测试用例与执行记录

基线：当前仓库 v0.1.0；日期：2026-09-20。接口定义见 [API.md](API.md)。本文件包含可按步骤执行的用例设计及本次已有自动化测试的实际结果，不将未运行场景标记为通过。

## 1. 范围与执行环境

覆盖浏览器侧 HTTP/SSE、M3→M1 输入文件、M2→M3 结果文件、错误处理、引用完整性、审计/历史/已读持久化、原始副本保留。真实检测准确率、M1/M2 算法、真实模型质量和大规模并发需在相应依赖就绪后另行验收。

优先级：P0 为主链路或结果可信性，P1 为异常/边界/恢复，P2 为体验及扩展验收。

自动化执行（Python≥3.11，已安装 requirements.txt）：

```powershell
python -m unittest test_workspace test_m3_acceptance -v
```

测试使用 TemporaryDirectory、独立 SQLite、随机本地端口，并在子进程中关闭 LLM，不写入正在运行站点的数据目录。不要使用旧 `test_flow.py` 对正式数据环境执行验收，该脚本会写演示任务到运行中的服务。

手工测试应另起隔离服务，避免复用项目 data/shared_workspace：

```powershell
$caseRoot = Join-Path $env:TEMP ('netguard-manual-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $caseRoot | Out-Null
$env:NETGUARD_DATA_DIR = Join-Path $caseRoot 'data'
$env:NETGUARD_WORKSPACE = Join-Path $caseRoot 'shared'
$env:NETGUARD_LLM_ENABLED = '0'
python -m uvicorn server:app --host 127.0.0.1 --port 18001
```

若端口被占用则换空闲端口。手工命令中的路径和 task_id 均须来自该隔离实例。需要完成任务时，在另一个终端针对上面的实际 shared 路径执行：

```powershell
python demo_bundle.py TASK_ID --workspace '实际隔离目录/shared'
```

该生产器只用于接口联调，固定结果与上传内容无关。文件协议负例应在隔离目录构造；更改 bundle 内容以测试语义校验时要重新计算 manifest.sha256，否则只会命中摘要错误。生产流程仍要求 READY 不可变，测试篡改 READY 专用于验证拒绝行为。

## 2. 测试数据与通用步骤

| 代号 | 数据/准备方法 |
|---|---|
| F1 | 非空 UTF-8 CSV，例如表头 timestamp,src_ip 及一行数据 |
| F2 | 完整 JSON 对象、JSON 数组和逐行对象 JSONL，各一份 |
| F3 | 真实可读 XLSX、PCAP、PCAPNG，各一份 |
| F4 | 零字节文件、txt、改名为 csv 的 MZ/PDF/ZIP、伪 XLSX/PCAP，各一份 |
| Q | 上传 F1，再 POST /tasks，尚无模块状态/结果的任务 |
| R | 为 Q 写入 M1 Status.v1：RUNNING、progress=40、message=M1 降噪中 |
| C | 为新 Q 调用 demo_bundle.produce；GET 任务确认 completed |
| X | 为新 Q 写 FAILED 状态或无效结果，再 GET 确认 failed |
| B | produce 产生的合法 bundle；从中取真实告警 ID、攻击链 ID、事件 ID |

共用请求体：创建任务 `{"file_ids":["实际file_id"],"query":"测试分析"}`；问答 `{"task_id":"实际task_id","message":"总结并解释证据"}`。所有 ID 必须使用同一用例中真实返回值，除非明确测试不存在情况。

## 3. HTTP、上传与任务用例

以下“预期”基于当前实现；实际执行状态统一见第 8 节，不代表表中所有条目已经自动化。

| ID | 优先级 | 前置/输入 | 操作步骤 | 预期结果 |
|---|---|---|---|---|
| H01 | P0 | 服务启动，LLM=0 | GET /health | 200，status=ok、mode=shared_files、llm=disabled |
| H02 | P1 | LLM 开关=1，无模型连通保证 | GET /health | llm=configured；不据此判定模型可用 |
| H03 | P2 | 服务启动 | GET /docs、/openapi.json | 200，可查看接口及请求模型 |
| F01 | P0 | F1 | multipart 字段 file 上传；计算输入 SHA256 | 200，ID 非空、size 与字节数相符、sha256 相符；副本内容一致 |
| F02 | P1 | F2、F3 | 各格式分别上传，另用大写 .CSV | 格式合法时均 200；扩展名大小写不敏感 |
| F03 | P1 | txt 文件 | 上传 | 400，detail=FILE_400: 不支持该格式；不新增有效记录 |
| F04 | P1 | 空 csv | 上传并查看隔离 data | 400，detail=文件为空；失败副本已删除 |
| F05 | P1 | 无 file 字段 | POST /files | 422，detail 为校验数组 |
| F06 | P1 | F4 伪造内容 | 分别上传 csv/xlsx/pcap/pcapng | 400，具体内容头错误；清理失败副本 |
| F07 | P1 | json 首个有效字符为 x | 上传 | 400，JSON 文件头无效 |
| F08 | P1 | 字节为 `{broken` 的 json | 上传 | 当前 200；记录仅做文件头检查，不能声称完整 JSON 解析通过 |
| F09 | P1 | 合法文本 2 GiB、2 GiB+1 字节；足够磁盘 | 分别上传 | 前者可接受，后者 413；超限失败无副本遗留。大文件测试需单独执行 |
| F10 | P1 | XLSX ZIP 成员超10000、解压总量超512 MiB、任一压缩比超500 | 分别构造并上传 | 400，规模/压缩比错误；不把 ZIP 中央目录检验当成完整 Excel 解析 |
| T01 | P0 | F1 已上传 | POST /tasks；检查 m3/READY 清单和副本 | 200，queued、0、transport=files；清单 ID 和 SHA256 匹配，STAGING 不再存在 |
| T02 | P1 | 两个已上传文件 | 创建任务 | 清单包含两个 source_files；task.filename 为第一个文件名 |
| T03 | P1 | 无 query | 创建任务 | query 及 user_prompt 为空字符串 |
| T04 | P1 | file_ids=[] 或缺省 | 创建任务 | 422，不产生有效任务 |
| T05 | P1 | 不存在的 file_id | 创建任务 | 400，FILE_400: 文件不存在 |
| T06 | P1 | 隔离实例中的文件已标记 raw_expired | 创建任务 | 410，提示重新上传 |
| T07 | P0 | 上传后篡改 data 副本 | 创建任务 | 400，任务文件投递失败且含 checksum 原因；无成功任务/READY 发布 |
| T08 | P1 | Q、C 等多个任务 | GET /tasks 和各详情 | 200，返回实际任务并刷新状态；不假定列表排序或分页 |
| T09 | P1 | 随机不存在 task_id | GET 详情/alerts/bundle/audit/chat-history/stream；POST retry/view-alert；请求 chat/report | 均 404 TASK_404（请求体本身须合法） |
| T10 | P0 | Q | 获取详情、alerts、bundle | queued、0；alerts=[]、chains=[]、chain=null；bundle 接口返回 {} |
| T11 | P0 | R | GET 详情；再写 M2 RUNNING=60 后查询 | 首次 running、20；两模块后 running、50；module_statuses 含模块名 |
| T12 | P0 | M1/M2 均 COMPLETED=100，无结果包 | 查询详情 | running、99，不误报 completed |
| T13 | P0 | 合法 B、degraded=true | 发布结果并查询 | completed、100、degraded=true；告警、链、bundle 可读 |
| T14 | P0 | 合法 B，同时 M1 FAILED | 查询详情及结果 | failed 优先；alerts/chains 清空、chain=null、bundle 接口 {} |
| T15 | P1 | X | POST retry | 200，新 task_id、相同 file_ids/query、queued；旧任务保留 |
| T16 | P1 | Q、R、C | 各 POST retry | 409，只有失败任务可以重试 |
| T17 | P1 | X 引用过期副本 | POST retry | 410，不生成可用新任务 |
| T18 | P1 | 同一创建请求 | 连续提交两次 | 两个不同 task_id；当前无创建幂等语义 |

## 4. 文件契约、结果与报告用例

| ID | 优先级 | 前置/输入 | 操作步骤 | 预期结果 |
|---|---|---|---|---|
| W01 | P0 | 只有 m2/STAGING 结果 | Workspace.read_bundle；查询任务 | read_bundle 返回 None，未完成结果不可见 |
| W02 | P0 | 已发布 B | 改 bundle 字节、不改摘要；查询 | 结果校验失败；任务 failed；旧告警/链不再暴露 |
| W03 | P0 | B 副本 | 分别修改 manifest schema_version/task_id、bundle schema_version/task_id | 摘要同步后仍拒绝，不挂接到其他任务 |
| W04 | P0 | B 副本 | 删除一个版本键；或改为空白 | ValueError/验证错误，任务 failed |
| W05 | P0 | B 副本 | 删除证据；或制造空/重复 event_id | 拒绝整个 bundle |
| W06 | P0 | B 副本 | 告警 event_ids=[] 或引用不存在证据 | 拒绝整个 bundle |
| W07 | P1 | B 副本 | 告警缺标题、重复 ID、severity=urgent、confidence=-0.1/1.1 | 每个变体均拒绝；info 等合法等级与0/1边界应接受 |
| W08 | P0 | B 副本 | 链重复 ID、stage 重复 ID、stage 无效证据或 edge 指向不存在 stage | 每个变体均拒绝 |
| W09 | P1 | B 副本 | stage confidence 超范围、time_range 长度1或3 | 拒绝；两个任意字符串当前不会强校验日期语义，应单独记录此限制 |
| W10 | P0 | B 副本 | profile/relationship 缺失证据引用；profile 引用未知链 | 拒绝整个 bundle |
| W11 | P1 | B 副本 | report 建议 source 缺失或非法 | 拒绝；四种合法 source 分别接受 |
| W12 | P1 | B 副本 | chain 增加 optional_note 后校验 | 扩展字段保留，不被静默丢弃 |
| W13 | P1 | 状态文件 | 分别用错误版本/任务ID/状态枚举、progress=-1/101 | 查询任务 failed，阶段提示文件契约错误 |
| W14 | P0 | Workspace 实例 | read_bundle('../escape') | ValueError，无目录越界读取 |
| W15 | P1 | 已完成任务 | 读取结果后删除 READY 结果目录，再查询 | 清除缓存及 bundle/alerts/chains；有状态则 running，否则 queued |
| A01 | P0 | C | GET alerts，与 bundle 对照 | event_ids 保留；evidence 为真实引用摘要；mitre 映射 technique |
| A02 | P0 | C 的 chain_id | GET attack-chains/{id} | stages/edges 保留，nodes 对应 stage_id，证据去重且 explanation 对应报告摘要 |
| A03 | P1 | 不存在 chain_id | GET 攻击链 | 404，攻击链不存在 |
| A04 | P0 | C，证据含邮箱及 password/token 文本 | GET bundle、详情、JSON 报告 | bundle 中匹配的敏感值已脱敏，正常证据引用可解析；不扩大为原始上传文件已脱敏 |
| P01 | P0 | C | 下载默认格式和 format=json | 200 application/json；attachment 文件名正确；JSON 含完整任务与 bundle |
| P02 | P0 | C | 下载 format=pdf 并打开 | 200 application/pdf；以 %PDF- 开始，文件名正确；人工检查中文、分页、证据、版本与建议来源 |
| P03 | P1 | Q、R、X | 下载任意报告 | 409，任务尚未完成 |
| P04 | P1 | C | format=xml/PDF | 400，仅支持 json/pdf；请求仍产生 report.export 审计 |
| P05 | P1 | Q | format=xml | 先返回409；完成条件先于格式校验 |

## 5. SSE、问答与持久化用例

| ID | 优先级 | 前置/输入 | 操作步骤 | 预期结果 |
|---|---|---|---|---|
| S01 | P0 | Q | 建立进度连接，再投递 RUNNING 和合法结果 | text/event-stream；依次可收到当前/变化快照，终态 completed 后关闭；没有固定次数承诺 |
| S02 | P1 | Q | 收到首次事件后保持状态不变1秒 | 不重复发送 progress；测试读取必须有超时，避免无限等待 |
| S03 | P1 | C 或 X | 建立进度连接 | 发送终态 progress 后关闭；C 为100%，X 不要求进度归零 |
| S04 | P1 | R | 断开连接，变更状态后重新连接 | 获取最新快照，不要求历史回放；客户端终态关闭 EventSource |
| C01 | P0 | C，LLM=0 | POST chat，消费完整流 | 200；status→一个或多个delta→evidence→done；done.degraded=true；可检索问题含有效证据引用 |
| C02 | P1 | Q、R、X | 发送合法问答体 | 409，请等待任务完成，不建立成功 SSE |
| C03 | P1 | C | message=''、4001字符或缺失 | 422；1字符、4000字符通过长度验证 |
| C04 | P1 | C | message 为纯空格 | 当前可通过长度验证；不得在文档承诺拒绝空白 |
| C05 | P0 | C 与另一任务的链 | 指定另一任务 chain_id 提问 | 404，攻击链不属于当前任务 |
| C06 | P0 | 多链任务 | 指定当前链提问 | 检索 task_evidence 引用属于选中链；全任务统计仍可出现，不声称回答所有内容仅限该链 |
| C07 | P0 | C | 问 xyz-nonexistent-49999 | 本地回答明确没有匹配任务证据；引用为空；degraded=true |
| C08 | P1 | C、本地 knowledge 可用 | 问“解释证据” | 同时提供知识引用并标 source_type=knowledge，不把知识当成本任务事实 |
| C09 | P1 | 隔离本地模型桩：超时/错误JSON/未知引用/空引用 | 启用模型后逐项问答 | 回退本地答案，done.degraded=true，不输出伪造引用；不请求真实外部服务 |
| C10 | P1 | 隔离模型桩返回非空答案和已知引用ID | 问答并消费流 | done.degraded=false，仅返回允许的引用；与 bundle.degraded 独立 |
| C11 | P1 | C | 对流按任意网络分片解析 | 正确重组 UTF-8、空行边界及 delta；每段 text≤80字符，不依赖传输块大小 |
| D01 | P0 | C 的告警 | 标记已读两次，查询 read-alerts | 每次 {ok:true}；复合键只有一行；审计有两次 alert.view |
| D02 | P1 | C，未知 alert_id | 标记已读 | 404，告警不存在；不新增已读记录 |
| D03 | P0 | C | 完成一次问答，读取 chat-history | 新增一条含 at/question/answer/citations；citations 字符串可二次 JSON 解析 |
| D04 | P1 | 同一任务完成51次问答 | 查询 chat-history | 最多50条，保留最近50条，返回顺序从旧到新 |
| D05 | P1 | 同一任务产生101次已读审计 | 查询 audit | 最多100条，按at降序；detail为含actor/detail的JSON字符串 |
| D06 | P0 | 有已读、聊天和报告的 C | 停止隔离服务，用同一目录重启 | 任务重新读取结果仍 completed；已读、历史、审计可恢复 |
| D07 | P1 | 有 Q/R 的实例 | 用相同目录重启并发布结果 | 等待任务恢复，随后可 completed，无需重新上传 |
| D08 | P1 | C、含敏感值的问题 | 问答后查询历史/审计 | 问题中的匹配敏感值被脱敏；审计问题详情只保留原问题前200字符再脱敏 |

## 6. 保留策略与人工联调用例

| ID | 优先级 | 前置/输入 | 操作步骤 | 预期结果 |
|---|---|---|---|---|
| R01 | P0 | 超TTL文件，被queued任务引用 | 调用 expire_uploads，显式传 now | 不删除，返回空清理列表 |
| R02 | P0 | 同一记录的任务改 completed | 再调用 expire_uploads | 删除 data 副本，返回 file_id，元数据 raw_expired=true |
| R03 | P1 | 一个文件被 completed 与 running 两任务引用 | 执行清理 | 任一非终态引用即保留 |
| R04 | P1 | 无任务引用的过期上传 | 执行清理 | 可清理；未达到TTL的不清理 |
| R05 | P1 | TTL=0/-1 或旧记录无上传时间 | 执行清理 | 不清理 |
| R06 | P0 | M3 READY/DONE、M1 PROCESSING及用户原件均有副本 | 对终态过期文件清理 | 只清理M3自有 data/READY/DONE副本；其他目录不变，符号链接不跟随删除 |
| R07 | P1 | 已清理记录 | 再次清理；尝试创建任务 | 不重复清理；创建任务410 |
| U01 | P0 | 隔离实例和可发布结果 | 浏览器上传→创建→等待→完成→告警/链→问答→导出 | 页面与API真实数据一致，等待不显示虚构结果，错误提示可见 |
| U02 | P1 | C、至少51条告警 | 筛选等级/关键字/时间/置信度，切换第2页 | 页面过滤和50条分页正确；这是前端行为，不是HTTP分页 |
| U03 | P1 | 多阶段分支链、多个画像及引用 | 缩放/复位/点节点/查看画像 | 方向和证据引用正确，不新增上游没有的阶段或关联 |
| U04 | P1 | 等待中和已完成任务 | 刷新浏览器、切换历史任务 | 选中状态与订阅恢复；已读和历史不丢失 |
| U05 | P1 | C，接口故障或SSE中断 | 中断请求、恢复连接 | 不永久显示成功或无响应；未收到done的回答不当成完整结果 |
| U06 | P0 | M1/M2正式产物和实际样本 | 完整真实模块联调，校对版本与证据 | 真实状态/结果可消费、标签列不被M1用作答案；需M1/M2参与，无演示替代 |
| U07 | P2 | 约定的数据量和并发数 | 执行压力及长时运行测试 | 记录耗时、内存、SSE连接数、错误率；性能门槛需团队约定，当前无已通过指标 |

## 7. 自动化映射与未覆盖边界

一个自动化方法包含多个断言，不能把方法数当成完整测试矩阵的已执行条数。

| 现有自动化方法 | 已有断言对应的覆盖 |
|---|---|
| WorkspaceTests.test_atomic_task_with_checksum | T01 的原子发布与manifest版本；使用简化输入记录 |
| WorkspaceTests.test_tampered_bundle_rejected | W02 的读取成功后篡改拒绝 |
| WorkspaceTests.test_missing_evidence_rejected | W05/W06 的证据删除导致引用失败 |
| WorkspaceTests.test_staging_invisible_and_path_rejected | W01、W14 |
| Acceptance.test_lifecycle_and_restart | F01/T01/T10/T13主链路、P03/C02阻断、D01首次已读、C01基本事件与引用、D03历史数量、P01状态码、P02文件头、D06任务/已读/审计恢复、W02清空结果 |
| Acceptance.test_validation_and_retrieval | C07/C08本地检索、W12扩展保留、W04缺model_version、F06伪csv/xlsx/pcap的函数校验、A04脱敏函数 |
| Acceptance.test_retention_waiting_and_completed | R01/R02基础路径及data副本删除 |

上述映射只代表已有断言覆盖的部分。例如当前生命周期测试并未逐字段断言上传摘要、报告下载头、PDF中文布局、SSE进度终态、重启后的聊天历史内容；伪文件校验为函数级而非HTTP级。边界大小、422输入组合、重试、状态聚合、真实模型/故障桩、批量历史上限、前端及性能用例尚需按表补执行或新增自动化。

`test_contracts.py` 是旧展示模型的 pytest 样例，不等同于本文件协议验收，本次未计入执行结果。

## 8. 本次执行记录

执行日期：2026-09-20。解释器：本机 Python 3.12（`E:\python\python.exe`）。

```text
命令：python -m unittest test_workspace test_m3_acceptance -v
test_atomic_task_with_checksum ... ok
test_missing_evidence_rejected ... ok
test_staging_invisible_and_path_rejected ... ok
test_tampered_bundle_rejected ... ok
test_lifecycle_and_restart ... ok
test_retention_waiting_and_completed ... ok
test_validation_and_retrieval ... ok
Ran 7 tests in 3.733s
OK
```

结果：7个现有自动化测试方法通过、0失败；隔离目录运行。第3～6节中未被第7节现有断言覆盖的步骤均为**待执行**，不能据本记录宣称全部接口边界、UI、性能、真实模型和真实算法验收通过。

后续执行请按以下模板逐项填写，状态使用“通过/失败/阻塞/未执行”：

| 用例ID | 代码版本/环境 | 实际结果与响应证据 | 状态 | 缺陷编号 | 执行人/时间 |
|---|---|---|---|---|---|
| 示例：F09 | 待填 | 待填；记录输入实际字节数及HTTP状态 | 未执行 | — | — |

发布验收建议：P0用例全部实际执行通过；P1失败项记录并评估影响；真实模块/真实LLM依赖未就绪时明确标为阻塞。演示联调通过只能说明M3能消费约定数据，不能代表检测效果或真实模型验收通过。
