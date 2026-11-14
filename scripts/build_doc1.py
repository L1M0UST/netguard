"""在官方模板骨架上原位填充技术文档内容（保留模板全部样式）。

用法: D:/python3.11/python.exe scripts/build_doc1.py
输出: docs/"九天·梧桐"AI+数据创新赛道-技术文档-NetGuard.docx
"""
from __future__ import annotations

import copy
import shutil
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

PROJECT = Path(__file__).resolve().parents[1]
TEMPLATE = Path(r"E:\platform_taishi\taishi_platform\m3\九天·梧桐”AI+数据创新赛道\“九天·梧桐”AI+数据创新赛道-技术文档模板.docx")
OUT = PROJECT / "docs" / "“九天·梧桐”AI+数据创新赛道-技术文档-NetGuard.docx"

NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'


def para_xml(style: str | None, text: str, page_break: bool = False) -> str:
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/>' + ('<w:pageBreakBefore/>' if page_break else '') + '</w:pPr>' if style else \
          ('<w:pPr><w:pageBreakBefore/></w:pPr>' if page_break else '')
    run = f'<w:r><w:t xml:space="preserve">{escape(text)}</w:t></w:r>' if text else ''
    return f'<w:p {NS}>{ppr}{run}</w:p>'


def table_xml(rows: list[list[str]], widths: list[int] | None = None) -> str:
    total = sum(widths) if widths else 9000
    n = len(rows[0])
    widths = widths or [total // n] * n
    grid = ''.join(f'<w:gridCol w:w="{w}"/>' for w in widths)
    body_rows = []
    for r_i, row in enumerate(rows):
        cells = []
        for c_i, cell in enumerate(row):
            bold = '<w:b/>' if r_i == 0 else ''
            shading = '<w:shd w:val="clear" w:color="auto" w:fill="DCE6F1"/>' if r_i == 0 else ''
            cells.append(
                f'<w:tc><w:tcPr><w:tcW w:w="{widths[c_i]}" w:type="dxa"/>{shading}<w:vAlign w:val="center"/></w:tcPr>'
                f'<w:p {NS}><w:pPr><w:spacing w:line="240" w:lineRule="auto"/></w:pPr>'
                f'<w:r><w:rPr>{bold}<w:sz w:val="18"/></w:rPr><w:t xml:space="preserve">{escape(str(cell))}</w:t></w:r></w:p></w:tc>')
        body_rows.append(f'<w:tr>{"".join(cells)}</w:tr>')
    borders = ('<w:tblBorders>' + ''.join(
        f'<w:{side} w:val="single" w:sz="4" w:color="B0B7C3"/>' for side in
        ('top', 'left', 'bottom', 'right', 'insideH', 'insideV')) + '</w:tblBorders>')
    return (f'<w:tbl><w:tblPr><w:tblW w:w="{total}" w:type="dxa"/>{borders}'
            f'<w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid>{grid}</w:tblGrid>'
            + ''.join(body_rows) + '</w:tbl>')


def build_content() -> list[str]:
    """按模板骨架样式生成正文段（章=3 节=4 正文=17 Title=10 表格=raw）。"""
    c: list[str] = []
    add = c.append

    # ---- 封面 ----
    add(para_xml('10', '“九天·梧桐”AI+数据创新赛道'))
    add(para_xml('10', '技术文档'))
    add(para_xml('3', '赛题二：网络安全态势智能感知'))
    add(para_xml('4', 'NetGuard —— 大规模 AI 智能安全研判平台'))
    add(para_xml('17', '团队名称：NetGuard 团队'))
    add(para_xml('17', '技术路线：多模态降噪 → 小-大模型级联研判 → 攻击链反幻觉校验 → 人机交互运营'))
    add(para_xml('17', '日期：2026 年 9 月'))

    # ---- 章1 项目概述 ----
    add(para_xml('3', '一、项目概述', page_break=True))
    add(para_xml('4', '1.1 赛题理解与设计目标'))
    add(para_xml('17', '传统态势平台生成的安全告警信息庞大，人工分析工作量巨大，海量告警与有限人力的矛盾突出。'
                     '本团队研发 NetGuard 智能安全研判平台，围绕"数据进得来、噪声降得下、攻击判得准、链条串得起、'
                     '报告出得来、人来问得动"六个目标，构建"机器为主、人工为辅"的全自动研判体系。'
                     '平台由三位成员的模块整合而成：M1 多模态降噪管线、M2 攻击链研判引擎、M3 前端交互层，'
                     '并自研契约转换（bridge）、结果组装（bundle）与全链编排（orchestrator）三个整合层。'))
    add(para_xml('4', '1.2 核心功能总览'))
    add(para_xml('17', '（1）支持 CSV / XLSX / JSON / JSONL / PCAP / PCAPNG 六种格式上传，多模态数据统一进入'
                     '同一条降噪研判管线；（2）四层智能降噪（无意义过滤、内容指纹去重、白名单、SimHash 复核压缩）；'
                     '（3）规则引擎、本地垂域模型与云端大模型三级研判；（4）攻击链构建、攻击者画像、威胁要素提取；'
                     '（5）风险事件报告（JSON + 结构化中文 PDF）；（6）智能问答、一键自动调查、威胁情报查询、'
                     '运营总结等人机交互能力；（7）万级告警分钟级处理。'))
    add(para_xml('17', '实测性能：官方 1.1 万条数据集全链智能模式 6 分 36 秒～8 分 22 秒，极速模式（纯规则+本地模型）'
                     '2 分 28 秒；M1 单机 10 万行 CSV 基准 10.5 秒；M2 关联吞吐约 2500 事件/秒。'))
    add(para_xml('4', '1.3 总体架构'))
    add(para_xml('17', '系统分五层：交互层（M3 BFF+前端，负责上传、进度、结果呈现与人机交互）、编排层'
                     '（Orchestrator 监听投递目录并驱动全链，实时镜像各模块进度）、降噪层（M1）、研判层（M2）、'
                     '模型层（本地 cqsec 垂域模型 + 云端 DeepSeek）。模块间唯一交换方式为"共享工作区 + 版本化'
                     '数据契约 + 原子文件投递"，无任何内部 RPC——每个模块可独立运行、独立测试、崩溃后可恢复。'))
    add(table_xml([
        ['阶段', '输入', '处理', '输出', '规模（1.1万条实测）'],
        ['上传', 'CSV/XLSX/PCAP 文件', '魔数校验+SHA-256', 'm3/READY 投递清单', '11,000 行 / 1.04MB'],
        ['M1 接入映射', '原始文件', '魔数判型+三级Schema映射', '标准化事件', '11,000 事件'],
        ['M1 降噪检测', '标准化事件', '四层过滤+11条规则+三源IOC+会话', '可疑会话', '10,955 → 6,631 会话'],
        ['M1 级联研判', 'Top 1% 候选', '本地cqsec先判→低置信升级云端', '语义判决', '110/110 本地判决'],
        ['bridge 转换', '会话级批次(契约2.0)', '事件展开+官方中文标签', '事件级批次(契约1.0.0)', '6,675 事件'],
        ['M2 关联研判', '事件级批次', '加权关联+ATT&CK+Top-60 LLM+反幻觉', '攻击链/告警/画像/报告', '6,577 链 / 889 画像'],
        ['bundle 组装', 'M2 五类结果', '引用闭合+消费方校验器自校验', 'AttackChainBundle.v1', '前端直接可读'],
        ['前端呈现', '结果包', 'SSE进度/筛选/链图/问答/调查/报告', '人机交互', '全功能'],
    ], [1800, 2200, 2600, 2200, 2000]))

    # ---- 章2 主流程与数据流向 ----
    add(para_xml('3', '二、主流程与数据流向', page_break=True))
    add(para_xml('4', '2.1 主流程八步详解'))
    add(para_xml('17', '第 1 步·多模态接入：读文件头 16 字节魔数判型（不信任扩展名）；PCAP 由自研纯 struct 解析器'
                     '提取五元组元数据，并按（源，目的，协议）聚合为"每流一行"的 GLYPH 文本摘要进入同一条管线——'
                     'CSV 与 PCAP 在语义层统一（多模态统一通道）。该做法与 2026 年 PCAP-LM/PacketGlyph'
                     '（arXiv:2607.28100）提出的"流量转 ASCII 语义摘要"思路一致。同源触达≥15 个目的端口即标记'
                     ' PORT_SWEEP，由 flow_scan 规则确定性检出端口扫描。'))
    add(para_xml('17', '第 2 步·Schema 三级映射：中英文别名表精确匹配 → 采样类型画像与启发式消歧 → 仍未识别字段'
                     '仅发送一次 LLM schema 级调用（置信度≥0.85 才采纳），映射方案按表头 SHA-256 冻结缓存，'
                     '后续记录全部程序转换、不再调用 AI——万级数据的映射成本是一次性的。'))
    add(para_xml('17', '第 3 步·智能降噪：四层过滤——无意义丢弃（无网络身份且无安全内容）、内容指纹+60 秒时间桶去重'
                     '（指纹不含时间，15 字段规范化 SHA-256）、IP/网段白名单、SimHash+LSH 近似复核分组（仅压缩展示'
                     '不删数据）。全部过滤路径带计数指标，前端实时可见"已处理 n 条、降噪后 m 条、去重 k 条"。'))
    add(para_xml('17', '第 4 步·规则+IOC 检测：11 条正则签名（SQL 注入/XSS/目录遍历/文件包含/命令注入/CSRF/'
                     'Java 反序列化/文件上传/扫描器/提示注入/端口扫描），匹配前做两轮 HTML 实体+URL 解码与 Base64 '
                     '附加解码；IOC 三源（手工配置、本地 SQLite 真实库——Spamhaus DROP + OpenPhish、可选微步在线）。'
                     '会话聚合采用五元组+300 秒不活动窗+3600 秒最大时长双切断，评分由规则分、频率、源活跃度、'
                     '资产关键性四组件构成，≥45 分判可疑。'))
    add(para_xml('17', '第 5 步·级联语义研判：候选严格限流（≤原事件 1%），每个候选先由本地微调垂域模型 cqsec'
                     '（Qwen3-4B QLoRA，自建 15340 条语料，16 类分类 macro-F1 97.05%）研判：16 类标签白名单校验、'
                     '置信度映射（高 0.9/中 0.7/低 0.45）；低于 0.5 或解析失败自动升级云端 DeepSeek-flash。'
                     '全量实测 110/110 候选全部由本地模型判决、云端调用 0 次。该设计是 FrugalGPT'
                     '（arXiv:2305.05176）/RouteLLM（arXiv:2406.18665）级联思想的工程化落地；SIABENCH'
                     '（arXiv:2603.06422）亦支持"初筛用小模型、深度分析用强推理"的分档范式。'))
    add(para_xml('17', '第 6 步·契约转换：M1 产物为会话级且缺少 M2 必填字段，直连会被静默丢弃。整合层按'
                     ' related_event_ids 把可疑会话展开回事件级（保留时间戳供时间衰减关联），会话级结论复制到'
                     '成员事件，并经"官方中文标签层"把英文规则名确定性映射为赛题 8 类中文标签'
                     '（不使用任何 ground truth 列，无命中标"待研判"）。'))
    add(para_xml('17', '第 7 步·关联研判：两两加权评分（时间 0.30/攻击者 0.25/受害者 0.20/端口 0.10/协议 0.05/'
                     '行为 0.10，共享 IOC +0.15、同会话 +0.10），"不同攻击者且无共享 IOC"一票否决，≥0.55 经并查集'
                     '合并；本地 ATT&CK 知识库（14 战术/34 技术）确定性首遍映射；Top-60 候选送云端 LLM 研判'
                     '（结构化 JSON 输出+严格校验），其余候选自动走规则链，覆盖率 100%。'))
    add(para_xml('17', '第 8 步·反幻觉校验与评分报告：LLM 结论的每条证据必须回溯到真实事件、每个技术必须在候选集内，'
                     '幻觉定量扣分（每项 0.05、确认幻觉 +0.25）且全阶段无效则整链退回规则结论；8 因子可解释评分'
                     '（战术严重度 0.22/证据强度 0.16/IOC 0.14/资产 0.12/规则分 0.12/LLM 0.08/链长 0.08/多阶段 0.08）；'
                     '攻击者画像坚持归因纪律（无证据一律 Not Determined）；最终结果经引用闭合校验后组装为'
                     ' AttackChainBundle.v1 投递给前端。'))
    add(para_xml('4', '2.2 中间产物的接力（二程数据）'))
    add(para_xml('17', '平台的数据流是"接力"式的：标准化事件落盘后既供降噪检测，也作为证据索引；可疑会话既触发'
                     '级联研判，也被展开为事件级；攻击链的评分因子被组装为置信度卡片，同时渲染为前端 SVG 与 PDF '
                     '攻击链表；最终 AttackChainBundle.v1 是问答、自动调查、情报查询、PDF 报告的共同数据源。'
                     '大载荷只落盘一次（event_details.parquet），分析层仅保留 512 字符语义证据——"重数据落盘、'
                     '轻证据入内存"的压缩设计是万级性能的基础之一。'))

    # ---- 章3 关键技术与创新点 ----
    add(para_xml('3', '三、关键技术与创新点', page_break=True))
    add(para_xml('4', '3.1 创新点一：小-大模型级联路由'))
    add(para_xml('17', '本地垂域模型作为研判第一档，云端大模型只处理低置信度样本。全量实测 110/110 候选由本地'
                     '模型判决、云端调用 0 次，云端研判成本趋近于零。依据：FrugalGPT（arXiv:2305.05176）证明级联'
                     '可数量级降低推理成本；TextReasoningBench（arXiv:2603.19558）实测长思维链对分类任务 token '
                     '膨胀 10-100 倍仅换来 1-3% 提升，佐证"分类用小模型、推理用大模型"的分档；SIABENCH'
                     '（arXiv:2603.06422）确立安全告警初筛的分档评测范式。'))
    add(para_xml('4', '3.2 创新点二：反幻觉证据校验与置信度卡片'))
    add(para_xml('17', 'LLM 结论实行"证据责任制"：引用的事件必须真实存在、引用的技术必须在候选集内、实体必须有'
                     '证据支撑，违规定量扣分并可能整链降级为规则结论。8 因子评分与反幻觉扣分合并为"置信度卡片"，'
                     '在报告、问答、前端三处共用，可现场演示"喂入噪声证据看扣分"。依据：RHINO（arXiv:2510.14233）'
                     '三段式 ATT&CK 抗幻觉；DeepFaith（arXiv:2607.24348）证明证据锚定可将报告忠实度从 0.68 提升至'
                     ' 0.92。多数开源 SOC 大模型项目没有评测与反幻觉体系，这是本平台最强的差异化点。'))
    add(para_xml('4', '3.3 创新点三：PCAP→Glyph 多模态统一通道'))
    add(para_xml('17', '不还原载荷，把包级元数据聚合为"每流一行"的文本摘要，使 PCAP 与 CSV 在语义层统一进入同一'
                     '降噪管线，端口扫描以"同流≥15 目的端口"阈值确定性检出。依据：PCAP-LM/PacketGlyph'
                     '（arXiv:2607.28100，2026）提出流量转 ASCII 语义摘要进大模型窗口。'))
    add(para_xml('4', '3.4 创新点四：告警提示注入自防'))
    add(para_xml('17', 'LogInject（arXiv:2607.14493）指出告警原文进入大模型前可被投毒。本平台两层防御：'
                     '其一，注入模式注册为 L1 规则——对 AI 接口的注入探测本身就是可疑事件，进入正常研判管线；'
                     '其二，所有载荷在发送给任何大模型（本地或云端）前经沙箱化处理，命中片段替换为'
                     '"[注入内容已拦截]"并计数。安全比赛中"防自己的 AI"是稀有空位。'))
    add(para_xml('4', '3.5 创新点五：混合路由问答与数字同源'))
    add(para_xml('17', '统计类问题（"多少条/占比/最主要类型"）由系统直接作答——数字与页面指标卡同源，零幻觉、'
                     '零成本、零延迟；知识解释类问题路由到本地垂域模型，上下文注入"精确统计块+证据摘要"并明确'
                     '禁止推算。解决了大模型问答"数字与页面不一致"的行业通病。'))
    add(para_xml('4', '3.6 创新点六：契约化三级数据流水线'))
    add(para_xml('17', '三级契约（M1 会话级契约 2.0 → bridge 事件级契约 1.0.0 → M2 结果包 → AttackChainBundle.v1）'
                     '全部版本化、校验和落盘、原子投递；bundle 组装器在写出前用消费方校验器先验自检——引用不闭合'
                     '不出门。所有实体 ID 由内容确定性派生（SHA-256），同输入多次运行结果完全一致。'))

    # ---- 章4 系统实现 ----
    add(para_xml('3', '四、系统实现（功能与代码对应）', page_break=True))
    add(para_xml('4', '4.1 交互层功能'))
    add(para_xml('17', '文件上传（六格式魔数校验、XLSX 解压规模与压缩比防炸弹校验）；任务创建走文件协议投递；'
                     'SSE 以 0.25 秒推送双模块进度（Status.v1 契约）；任务分析面板逐段流式展示"数据解析与降噪中'
                     '（已处理 n 条）/模型研判（k/60）"；告警中心支持中文标题、等级/时间/置信度/关键字四维筛选与'
                     '分页；告警详情走轻量端点（单告警+关联链+证据切片，KB 级响应，先显示加载态再弹出）。'))
    add(para_xml('17', '特色交互：一键自动调查（SSE 轨迹流式展示"载入→情报富化→逐链调查→反幻觉校验→结论"）；'
                     '证据置信度卡片（8 因子条形图+惩罚项+反幻觉结论）；威胁情报查询（三层：离线 GeoIP 境内/境外'
                     '+本地 IOC 库命中→在线归属→可选信誉库，攻击类型命中本地 16 类知识库）；智能问答混合路由；'
                     'PDF/JSON 报告导出；演示重置（有任务运行时拒绝，全屏遮罩阻断）。'))
    add(para_xml('4', '4.2 降噪层核心实现'))
    add(para_xml('17', '多格式接入以魔数判型（4 种 PCAP 字节序+PCAPNG），PCAP 纯 struct 解析；Schema 三级映射见'
                     ' 2.1 第 2 步；去重指纹不含时间、无时间退化到事件 ID；IOC 本地库 72 小时过期原子替换；CSRF '
                     '规则 1.4 在保留原 token 降级特征的基础上，新增"敏感状态变更方法+攻击者载荷标记"组合判定'
                     '（去空白匹配容忍加号/编码混淆），官方数据集 942 条 CSRF 覆盖 934 条、正常流量零误报。'))
    add(para_xml('4', '4.3 研判层核心实现'))
    add(para_xml('17', '关联引擎按攻击者/受害者分块剪枝保持近线性复杂度；ATT&CK 知识库为数据驱动 YAML'
                     '（14 战术/34 技术），扩充知识无需改代码；攻击链构建坚持"一条事件只支撑一个阶段"，不虚构'
                     '多阶段叙事；攻击者画像的归因字段在无证据时固定为 Not Determined——不编造组织与国家。'))
    add(para_xml('4', '4.4 工程质量'))
    add(para_xml('17', '测试体系：M1 56 项、M2 约 201 例（单元/契约/集成/性能四层）、整合层 16 项，测试与运行时'
                     '数据隔离（固定种子情报目录），任何测试不触外部 API。可靠性：三级契约全部原子投递+校验和落盘，'
                     '幂等重放、租约认领、崩溃恢复齐备；状态上报失败绝不让任务失败；Windows 并发读写锁、'
                     '目录重命名占用、子进程管道排空三处典型工程修复保证演示稳定。大响应经瘦身与 GZip 压缩，'
                     '6577 条攻击链的任务列表从 70MB 降至 KB 级。'))

    # ---- 章5 测试与性能 ----
    add(para_xml('3', '五、测试与性能', page_break=True))
    add(para_xml('4', '5.1 功能与集成测试'))
    add(para_xml('17', '四层测试：单元测试覆盖各模块纯函数；契约测试验证文件协议与引用闭合（含负例：篡改摘要、'
                     '证据缺失、路径穿越均拒绝）；集成测试验证端到端流水线、幂等重放、崩溃恢复、租约互斥与各类'
                     'LLM 失败模式降级；性能测试验证万级吞吐。测试与运行时数据完全隔离，可离线复现。'))
    add(para_xml('4', '5.2 性能实测'))
    add(table_xml([
        ['场景', '数据量', '耗时', '说明'],
        ['智能模式全链', '11,000 条', '6m36s ~ 8m22s', '级联 110/110 本地判决，云端 0 次；M2 Top-60 云端研判'],
        ['极速模式（纯规则+本地模型）', '11,000 条', '2m28s', 'DEEPSEEK_ENABLED=0'],
        ['样本全链（演示）', '380 条', '约 30 秒', '端到端含报告'],
        ['PCAP 多模态全链', '54 包→3 流', '约 12 秒', '端口扫描检出 T1595'],
        ['M1 单机吞吐', '100,000 行', '10.5 秒', 'CSV 基准'],
        ['M2 关联吞吐', '10,000 事件', '约 4 秒', '约 2500 事件/秒'],
        ['情报查询/PDF 报告', '单次', '<1 秒 / 0.3 秒', '全离线；PDF 5 页'],
    ], [2600, 1800, 2200, 3200]))
    add(para_xml('17', '攻击类型覆盖：官方数据集 8 类攻击（SQL 注入、XSS、目录遍历、文件包含、远程命令执行、CSRF、'
                     'Java 反序列化、文件上传）全部精确检出，本地垂域模型候选集扩展至 16 类'
                     '（另含暴力破解、扫描探测、Webshell、C2 回连、SSRF、XXE、SSTI），为题型扩展预留能力。'))

    # ---- 章6 总结与展望 ----
    add(para_xml('3', '六、总结与展望', page_break=True))
    add(para_xml('4', '6.1 总结'))
    add(para_xml('17', 'NetGuard 实现了从多模态告警接入、智能降噪、级联研判、攻击链反幻觉校验到风险报告与'
                     '人机交互的完整闭环：1.1 万条官方数据 8 类攻击全覆盖、6-8 分钟出全量报告，云端大模型调用'
                     '被级联压缩至趋近于零，AI 结论每一条证据可回溯。平台由三位成员的模块经契约化整合而成，'
                     '测试 270+ 项全绿，工程可靠性经多轮全量演练验证。'))
    add(para_xml('4', '6.2 展望'))
    add(para_xml('17', '后续方向：（1）垂域模型持续训练——以平台运行产物构建"数据飞轮"，在昇腾 910B 云端扩展'
                     '训练级联研判头与生成类能力；（2）攻击链子图问答（GraphRAG 路线，检索答案升级为图上推理，'
                     '参考 arXiv:2608.13050：图检索规则在 IOC 轮换后 100% 有效 vs 朴素 RAG 29%）；'
                     '（3）PCAP 载荷级深度解析；（4）接入九天大模型 API 与更多威胁情报源，完善"机器为主、'
                     '人工为辅"的运营闭环。'))

    return c


def main() -> int:
    src = TEMPLATE
    work = PROJECT / 'docs' / '_doc1_work'
    work.mkdir(parents=True, exist_ok=True)
    docx_work = work / 'docx'
    with zipfile.ZipFile(src) as z:
        z.extractall(docx_work)

    doc_xml = docx_work / 'word' / 'document.xml'
    xml = doc_xml.read_text(encoding='utf-8')

    header_end = xml.index('<w:body>') + len('<w:body>')
    sect_start = xml.rindex('<w:sectPr')
    header, footer = xml[:header_end], xml[sect_start:]

    content = build_content()
    # 封面后分页：第一章前带 pageBreak
    body = ''.join(content)
    out = header + body + footer
    doc_xml.write_text(out, encoding='utf-8')

    # 重新打包
    if OUT.exists():
        OUT.unlink()
    with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as z:
        for f in sorted(docx_work.rglob('*')):
            if f.is_file():
                z.write(f, f.relative_to(docx_work).as_posix())
    shutil.rmtree(work, ignore_errors=True)
    print('生成:', OUT)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
