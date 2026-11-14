from pathlib import Path
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'NetGuard_竞赛演示视频操作流程与解说台词.docx'
doc = Document()
sec = doc.sections[0]
sec.top_margin = Inches(.68)
sec.bottom_margin = Inches(.68)
sec.left_margin = Inches(.78)
sec.right_margin = Inches(.78)

styles = doc.styles
for name in ('Normal', 'Title', 'Subtitle', 'Heading 1', 'Heading 2', 'Heading 3'):
    s = styles[name]
    s.font.name = 'Microsoft YaHei'
    s._element.rPr.rFonts.set(qn('w:eastAsia'), 'Microsoft YaHei')
    s.font.color.rgb = RGBColor(0, 0, 0)
    if s._element.pPr is not None:
        p_borders = s._element.pPr.find(qn('w:pBdr'))
        if p_borders is not None:
            s._element.pPr.remove(p_borders)
styles['Normal'].font.size = Pt(10)
styles['Normal'].paragraph_format.space_after = Pt(4)
styles['Normal'].paragraph_format.line_spacing = 1.12
styles['Title'].font.size = Pt(25)
styles['Title'].font.bold = True
styles['Subtitle'].font.size = Pt(12)
styles['Heading 1'].font.size = Pt(17)
styles['Heading 1'].font.bold = True
styles['Heading 1'].paragraph_format.space_before = Pt(8)
styles['Heading 1'].paragraph_format.space_after = Pt(6)
styles['Heading 2'].font.size = Pt(12)
styles['Heading 2'].font.bold = True
styles['Heading 2'].paragraph_format.space_before = Pt(6)
styles['Heading 2'].paragraph_format.space_after = Pt(3)

def shade(cell, fill):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd'); shd.set(qn('w:fill'), fill); tcPr.append(shd)

def borders(table):
    tblPr = table._tbl.tblPr
    b = OxmlElement('w:tblBorders')
    for edge in ('top', 'left', 'bottom', 'right', 'insideH', 'insideV'):
        e = OxmlElement('w:' + edge); e.set(qn('w:val'), 'single'); e.set(qn('w:sz'), '5'); e.set(qn('w:color'), 'D9E1EA'); b.append(e)
    tblPr.append(b)

def set_repeat_table_header(row):
    trPr = row._tr.get_or_add_trPr(); el = OxmlElement('w:tblHeader'); el.set(qn('w:val'), 'true'); trPr.append(el)

def table(headers, rows, widths=None, font_size=9):
    t = doc.add_table(rows=1, cols=len(headers)); t.alignment = WD_TABLE_ALIGNMENT.CENTER; t.autofit = False
    borders(t); set_repeat_table_header(t.rows[0])
    for i, text in enumerate(headers):
        c=t.rows[0].cells[i]; c.text=text; shade(c, '17365D'); c.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
        for p in c.paragraphs:
            p.paragraph_format.space_after=Pt(1)
            for r in p.runs: r.font.bold=True; r.font.color.rgb=RGBColor(255,255,255); r.font.size=Pt(font_size)
    for ri, vals in enumerate(rows):
        cells=t.add_row().cells
        trPr=t.rows[-1]._tr.get_or_add_trPr(); cant=OxmlElement('w:cantSplit'); trPr.append(cant)
        for i, val in enumerate(vals):
            cells[i].text=str(val); cells[i].vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
            if ri % 2: shade(cells[i], 'F2F6FA')
            for p in cells[i].paragraphs:
                p.paragraph_format.space_after=Pt(1); p.paragraph_format.line_spacing=1.05
                for r in p.runs: r.font.size=Pt(font_size)
    if widths:
        for row in t.rows:
            for i,w in enumerate(widths): row.cells[i].width=Inches(w)
    doc.add_paragraph().paragraph_format.space_after=Pt(1)
    return t

def p(text='', bold_lead=None, style=None):
    para=doc.add_paragraph(style=style)
    if bold_lead and text.startswith(bold_lead):
        para.add_run(bold_lead).bold=True; para.add_run(text[len(bold_lead):])
    else: para.add_run(text)
    return para

def bullet(text, level=0):
    para=doc.add_paragraph(style='List Bullet' if level == 0 else 'List Bullet 2')
    para.paragraph_format.space_after=Pt(2); para.add_run(text); return para

def step(title, time, screen, actions, narration, check=None):
    doc.add_heading(f'{time}  {title}', level=2)
    p('画面：' + screen, bold_lead='画面：')
    p('操作：' + actions, bold_lead='操作：')
    para=doc.add_paragraph(); para.paragraph_format.left_indent=Inches(.18); para.paragraph_format.right_indent=Inches(.12)
    r=para.add_run('解说词  “' + narration + '”'); r.italic=True; r.font.color.rgb=RGBColor(31,78,121)
    if check: p('检查点：' + check, bold_lead='检查点：')

def page_heading(title):
    heading = doc.add_heading(title, level=1)
    heading.paragraph_format.page_break_before = True

# Running footer with page number.
footer=sec.footer.paragraphs[0]
footer.alignment=WD_ALIGN_PARAGRAPH.RIGHT
rr=footer.add_run('NetGuard 竞赛演示拍摄手册  ·  '); rr.font.size=Pt(8); rr.font.color.rgb=RGBColor(95,105,120)
fld=OxmlElement('w:fldSimple'); fld.set(qn('w:instr'),'PAGE'); footer._p.append(fld)

# Cover / purpose.
para=doc.add_paragraph(); para.paragraph_format.space_before=Pt(50); para.alignment=WD_ALIGN_PARAGRAPH.LEFT
r=para.add_run('NetGuard'); r.bold=True; r.font.size=Pt(13); r.font.color.rgb=RGBColor(31,78,121)
doc.add_paragraph('竞赛演示视频操作流程与解说台词', style='Title')
doc.add_paragraph('按本手册完成一次可复现的系统演示和录屏', style='Subtitle')
p('版本日期：2026 年 9 月 23 日　|　建议成片：9–12 分钟　|　主流程数据：项目内合成万级告警集')
doc.add_paragraph()
doc.add_heading('这段演示要说明什么', level=1)
p('赛题关注海量告警带来的人工研判压力，要求工具支持多格式数据接入、万级快速处理、尽可能多的攻击类型识别，并提供风险报告与人机协同运营能力。本手册把这些要求对应到 NetGuard 的真实页面和操作中，按“上传数据—观察降噪与研判—核查告警证据—还原攻击链—给出处置依据—导出报告”的顺序录制。')
p('主流程使用由项目脚本生成的 10,200 行合成 CSV，规避在公开视频里展示来源/再分发许可尚待核实的团队工作簿。录制中只陈述当前屏幕和本机验收证据能支持的结论；合成数据结果不代表生产环境或主办方盲测成绩。')
doc.add_heading('建议成片结构', level=2)
table(['段落','时长','观众看到的结果'],[
 ['问题与平台定位','0:00–0:40','赛题痛点、目标和系统入口'],
 ['万级数据全链路','0:40–3:00','创建任务、处理进度、过滤和风险分布'],
 ['告警与攻击链取证','3:00–5:40','等级筛选、多阶段路径、原始证据'],
 ['置信度与自动调查','5:40–7:15','风险理由、证据闭合、自动调查轨迹'],
 ['情报、问答和报告','7:15–9:30','本地/在线情报、引用式问答、JSON/PDF'],
 ['技术边界与总结','9:30–10:00','数据边界、人工复核和结果交付']
], [1.55,1.15,4.25])
p('核心原则：镜头始终跟着一个分析任务走。无需在主片里展示所有菜单；每次点击都要回答“这个页面帮分析人员作什么决定”。')

page_heading('一 录制前准备')
doc.add_heading('1.1 设备和服务', level=2)
for x in [
 '在项目根目录 E:\\platform_taishi\\taishi_platform 双击 scripts\\start_all.bat，等待 Web/API、编排器以及配置存在时的本地模型服务启动。',
 '打开 http://127.0.0.1:8001，确认侧栏系统状态为正常；有本地模型服务时再确认 8008 可用。',
 '可在 PowerShell 运行：powershell -NoProfile -ExecutionPolicy Bypass -File scripts\\competition_preflight.ps1 -RequireRunningServices。通过后开始录制。',
 '录屏建议 1920×1080、浏览器缩放 90%–100%、鼠标移动放慢；关闭通知、无关窗口和会暴露 API 密钥的终端。使用清晰麦克风，系统字体保持可读。',
 '准备项目合成数据：tests_integration\\fixtures\\suite\\01_main_10k.csv（10,200 行）。这份生成数据包含正常样本、多个攻击场景、重复/白名单流量和跨阶段场景。'
]: bullet(x)
doc.add_heading('1.2 录制前先做一次完整彩排', level=2)
table(['确认项','怎么确认','异常时的处理'],[
 ['页面和端口','8001 页面能打开，侧栏状态正常；本地模型配置可用时再确认 8008','按统一启动脚本启动；不要现场临时修改密钥'],
 ['任务流程','先用演示数据跑完一次，确认出现完成状态、告警、攻击链和报告','若本地推理较慢，提前启动模型并预热；录屏可剪掉等待但保留真实进度'],
 ['数据与授权','主片使用项目生成的合成 CSV；不要上传生产日志或个人信息','团队工作簿授权未确认前，不放入公开录屏或提交包'],
 ['智能功能','预先检查自动调查、AI 情报查询和问答服务可用性','联网 AI 不可用时仍展示本地情报与规则证据，如实说明云端结果未返回']
], [1.12,2.85,2.98])
doc.add_heading('1.3 建议展示配置', level=2)
p('主任务建议选择“仅本地模型（数据不出本机）”，先以规则和 IOC 确定性筛选，再让本地模型处理候选项，减少录屏对外网和云端配额的依赖。若彩排确认网络、额度和回退都正常，也可选择默认的“本地初判 + 云端复核”；台词需按页面实际显示的任务策略念，不要说本次调用了某云厂商，除非任务记录明确显示。')
p('主任务备注可填“演示：检查扫描、注入与多阶段攻击证据”，但不要把结论预先写入备注。把文件放在桌面或资源管理器已打开的位置，避免录制时长时间寻找文件。')

page_heading('二 主视频逐步操作和台词')
step('开场和赛题问题','00:00–00:35','浏览器打开 NetGuard 的“态势总览”，镜头停留在页面标题与全局导航。','不点击功能按钮；用鼠标依次指向“态势总览、分析结果、告警中心、攻击链分析、分析任务”。','赛题面对的是海量安全告警和有限的人工研判能力。NetGuard 面向这一流程，接收多种格式的告警数据，先做确定性规则和情报筛选，再对候选事件研判，最后把风险、攻击链和证据交给分析人员复核。')
step('清理演示环境','00:35–00:50','侧栏底部“重置演示环境”。','点击“重置演示环境”，在页面询问时确认；等待遮罩提示“正在重置演示环境”，页面自动刷新后继续。','我先清理上一次演示产生的任务和结果，确保接下来展示的是同一份输入数据的新任务。','页面完成刷新，任务列表为空。重置会清理任务及工作区产物，不能在真实留存环境随意操作。')
step('创建万级分析任务','00:50–01:25','点击“新建分析任务”打开上传面板。','点击“点击选择文件或拖拽到此处”，选 `tests_integration\\fixtures\\suite\\01_main_10k.csv`；模型策略选择“仅本地模型”，备注写“竞赛演示：检查多阶段攻击链证据”；点击“开始分析”。','这次输入是项目内固定生成的 10,200 行合成告警，覆盖多类攻击和正常流量。策略选择本地模型，避免原始数据离开本机；规则与 IOC 初筛始终参与，模型主要复核被筛出的候选，而不是逐行把万条数据都发给大模型。')
step('观察处理进度','01:25–02:10','任务分析区和“分析任务”状态，页面按实际状态显示解析、筛选、M1、Bridge、M2 等进度。','保持页面，等状态从处理中变为已完成；可指向进度和阶段文字，避免快速滚动。','系统先读取文件并做字段映射和标准化。M1 使用白名单、去重、规则和 IOC 降噪，再让模型检查候选事件。Bridge 保留模型意见和证据引用，M2 根据事件事实与时间、资产等关系关联攻击链。每一层状态都在任务页面可见。','任务状态显示完成；记录本次任务实际显示的事件数和耗时，后面的台词只引用屏幕数字。')
step('浏览风险总览','02:10–02:45','返回“态势总览”，显示威胁类型和“危险等级占比”。','指向告警总量、各等级统计和分布图；停留数秒让镜头读完标签。','总览把任务中的告警和严重程度放在一起。低危、信息级是否出现取决于本次输入和过滤结果，不会人为补成固定比例。等级只是排序线索，后面还要回到事件证据判断处置优先级。','图表数字与当前任务一致；不要引用早期手册中已注明为历史预期的固定告警数。')

doc.add_heading('二 主视频逐步操作和台词 续', level=1)
step('筛选和查看告警','02:45–03:35','左侧点击“告警中心”。','在等级筛选器依次选一个高风险等级和“低危”；如有搜索框，按目标资产或攻击源查找；点击一条告警打开详情。','告警中心把事件按目标资产、等级和时间组织。筛选用于缩小排查范围；点开详情后可以看到攻击源、受害资产、时间、规则或情报命中以及关联链。这里的告警结论仍然要结合原始证据，不把模型摘要当作唯一依据。')
step('打开优先展示的多阶段攻击链','03:35–04:35','左侧点击“攻击链分析”，显示“查找并选择攻击链”、攻击路径图和工具栏。','点击“选择要查看的攻击链”下拉框，优先选名称或标记为多阶段的链；如果列表很长，用搜索框输入攻击源或受害资产。展示路径中的阶段数量和时间顺序。','攻击链分析把相关告警按攻击者、受害资产和时间先后组织起来。多阶段链优先展示，因为它能说明攻击行为之间的关联；单个阶段仍然保留来源和证据，链路排序不是把关联推断伪装成已证实事实。','攻击路径图确实显示节点/阶段；若选中单阶段链，换一条多阶段链，不要对空路径继续解说。')
step('沿路径展开原始证据','04:35–05:00','攻击路径图的任一阶段节点与下方证据区域。','点击其中一个阶段，展示技术名称、时间范围、置信度和事件证据引用；随后点击“② 攻击者画像”“③ 处置建议”“④ 证据与统计”。','点击阶段可以回到支撑这一环节的原始事件，而不是只看一条生成式总结。画像描述攻击源或目标资产的关联情况，处置建议要能追溯到观测到的行为，统计页用于核对链路证据和覆盖范围。')
step('查看置信度依据','05:00–05:35','回到“态势总览”或工作台工具区，点击“置信度卡片”。','点开一张攻击链卡片，指向 8 项评分因子、证据闭合检查和扣分项。','置信度卡片用于解释风险排序依据。它把资产重要性、规则评分、模型置信度等因素与证据完整性放在一起，也显示会降低可信度的因素。这个分值帮助分析人员确定复核顺序，不等同于统计学上的概率，也不替代人工判断。','只解释屏幕上实际显示的因子；不要说“置信度 90% 就有 90% 概率发生攻击”。')

page_heading('三 智能调查与情报查询')
step('运行一键自动调查','05:35–06:20','工作台工具区的“一键自动调查”，以及生成的调查轨迹。','点击“一键自动调查”，等待 SSE 轨迹完成；镜头展示优先选择的多阶段链、情报富化、路径分析、证据校验和结论。','自动调查会优先处理多阶段链，其余链再按严重程度和风险分排序。系统逐项读取已有证据并生成调查摘要与处置线索，分析人员可以沿链和证据回查。自动调查是辅助研判，不会自动执行隔离或封禁。','若轨迹仍在运行，等待完成后再继续；不要在部分输出时念最终结论。')
step('查本地 IOC 与任务关联','06:20–06:55','点击“威胁情报查询”，出现输入框和“查询”按钮。','输入 `1.19.66.77` 并点“查询”；如本次任务未关联到该地址，结果仍可展示本地 IOC 命中，但不要声称它出现在当前任务。','这里先查本地情报：离线归属、恶意 IOC 清单和当前任务关联会分开展示。命中本地情报能提供一个排查线索，但仍需结合证据来源、时间和资产上下文判断。','准确念出结果上的“命中/未命中”和数据源状态；如果离线库版本或结果与预期不同，以实际界面为准。')
step('查攻击知识与 AI 综合研判','06:55–07:35','情报查询面板和自动出现的 AI 综合研判区域。','再次输入 `SQL注入攻击` 并查询；展示 ATT&CK 技术、攻击简介、特征、处置建议和 AI 综合研判区域。等待 AI 返回或显示缓存状态。','查询攻击类型时，平台把本地攻击知识、ATT&CK 对照和处置线索集中呈现。AI 联合研判会按需综合可用证据并缓存结果；如果在线源不可达，本地查询结果仍然可以用，页面会标出不可达或失败，不把缺失结果补写成成功。','不展示 API Key、控制台或请求头；云端结果只按界面实际成功状态介绍。')
step('询问当前攻击链','07:35–08:10','返回攻击链页面，点击“询问这条攻击链”，打开 NetGuard 分析查询侧栏。','输入“这条链包含哪些攻击阶段？每个阶段有哪些证据？”，点击“发送”；等待流式答复和证据引用。','问答围绕当前任务或当前攻击链回答。统计类问题直接读取结构化结果；解释类问题给出摘要和引用事件。分析人员仍要点回原始证据核对，不把对话答案当成新的日志事实。','若问答还在流式生成，等结束；证据引用应能对应到已展示的告警或阶段。')

page_heading('四 报告交付与补充场景')
step('查看整体风险报告','08:10–08:45','点击侧栏“分析结果”。','滚动展示总体结论、风险分布、重点事件、优先处置建议和相关攻击链入口。','报告把研判结果转成便于交接的摘要。建议项应说明它对应的观测证据、风险原因和建议动作；例如发现异常外联时，进一步核对目标域名与传输内容，再按组织流程限制出口或调查主机。这里给出的是处置参考，不会替代授权审批。')
step('导出汇报版与证据包','08:45–09:10','分析结果右上方的“下载汇报版 PDF”和“下载证据包 JSON”。','分别点击两个按钮并确认浏览器下载；快速展示 PDF 报告页面和 JSON 证据包文件名。','PDF 用于快速阅读和汇报，JSON 保存结构化证据与机器可读结果，便于后续核对和系统集成。正式留档时还要记录任务编号、输入文件哈希、规则和模型版本，以及本次运行配置。','不要把整个 JSON 在视频里高速滚屏；展示文件成功下载和关键字段即可。')
doc.add_heading('可选补充镜头：PCAP 流元数据分析', level=2)
p('若成片时长允许，可在主流程完成后用另一条任务补拍 45–60 秒。先确认数据已留档，再点击“新建分析任务”，选择 `tests_integration\\fixtures\\suite\\05_attack_scenarios.pcap`，策略选本地模型并开始分析。完成后在告警/攻击链详情展示端口扫描摘要与 GLYPH 流证据。')
para=doc.add_paragraph(); para.paragraph_format.left_indent=Inches(.18); para.paragraph_format.right_indent=Inches(.12)
r=para.add_run('补充台词  “平台可以接收 PCAP/PCAPNG，并把当前支持范围内的 Ethernet/IPv4 流信息提取为摘要供后续规则研判。当前演示展示的是流元数据，不是 TCP 重组、TLS 解密或完整应用层协议取证。”'); r.italic=True; r.font.color.rgb=RGBColor(31,78,121)
p('该 PCAP 场景用于说明输入格式范围和处理边界。不要称它完成了完整的网络流量多模态语义理解。')
step('结尾总结','09:10–09:40','回到态势总览或分析结果页，停留在本次任务摘要。','鼠标依次指向任务结果、证据与导出入口，停顿后结束录制。','本次演示从万级告警输入开始，经过规则和 IOC 降噪、模型辅助研判、攻击链关联与人工证据复核，最后输出报告和结构化证据。我们把自动化用于减少重复筛查，把结论和原始证据一起交给分析人员确认。当前结果来自项目合成数据和本机验证，实际部署仍需结合授权数据、现场盲测和组织处置流程评估。')

page_heading('五 可选测试支线和故障处理')
doc.add_heading('5.1 多格式与安全场景支线', level=2)
table(['想补充的能力','输入文件','操作与建议台词','边界'],[
 ['XLSX 接入','tests_integration\\fixtures\\suite\\02_same_scenarios.xlsx','新建任务上传并展示同一场景可用 XLSX 进入处理流程。','不要把同内容格式对照说成独立准确率评估。'],
 ['JSONL 解析与无意义行过滤','tests_integration\\fixtures\\suite\\03_events.jsonl','展示输入中缺少有效网络身份且无内容的记录被过滤。','按运行结果说明过滤数，数值可能随版本变化。'],
 ['重复告警去重','tests_integration\\fixtures\\suite\\04_events.json','展示内容指纹和时间桶去重的计数。','讲清去重是减少重复事件，不代表删除了所有相似事件。'],
 ['提示注入防护','tests_integration\\fixtures\\injection_alerts.csv','展示输入中针对模型的恶意指令被拦截或替换，并观察对应状态指标。','安全载荷仅在隔离演示环境中展示。'],
 ['PCAPNG 输入','tests_integration\\fixtures\\suite\\06_attack_scenarios.pcapng','与 PCAP 场景同样创建任务，展示受支持范围内的流元数据结果。','不声称完整解析所有 PCAPNG 块和协议内容。']
], [1.28,1.95,2.5,1.3], font_size=8)
doc.add_heading('5.2 现场故障应对', level=2)
table(['现象','处理方式','镜头处理'],[
 ['任务长时间处理中','先看任务进度和编排器状态；本地模型初次启动可能较慢，彩排时提前预热。不要连续重复提交同一文件。','保留真实进度画面；必要时剪辑等待段，但不要伪造结束状态。'],
 ['情报在线源不可达','展示本地 IOC、知识库和每一层来源状态；可按项目代理配置检查网络后重试。','说明“在线源不可用，本地结果仍可用”，不要读出没有返回的数据。'],
 ['AI 联合研判失败','先展示基础情报查询结果；最多按页面提示重试一次。','保留错误状态或剪掉操作等待，但不可改写成模型成功。'],
 ['选中的攻击链没有路径','换一条明确的多阶段链；必要时按攻击源或受害资产过滤列表。','没有可见阶段就不要继续讲该链。'],
 ['PDF/JSON 没有下载','确认任务已完成，再回“分析结果”重试并检查浏览器下载栏。','未成功落盘就不要口播“已导出”。'],
 ['服务状态异常','停止录制；运行启动脚本和预检命令，再刷新页面。','修复后从干净页面重录，不用旧截图冒充实时页面。']
], [1.35,3.0,2.65], font_size=8)

doc.add_heading('5.3 拍摄结束后的清理', level=2)
for x in [
 '先确认已保存录屏和导出的 PDF/JSON，再点击侧栏“重置演示环境”清理演示任务。此操作会删除任务及工作区产物，需先确认没有要保留的证据。',
 '剪辑时打码任务输入路径中可能出现的个人目录、桌面通知、令牌、邮箱和主机名；API 密钥不可进入录屏、字幕、PPT 或提交包。',
 '片尾或字幕注明主演示样本为项目内生成的合成数据。若视频加入团队工作簿或真实 PCAP，先确认使用许可、脱敏和对外展示权限。'
]: bullet(x)

doc.add_heading('六 录制前核对表', level=1)
table(['完成','录制前检查'],[
 ['□','统一启动入口已运行；8001 页面可打开，服务状态正常。'],
 ['□','已彩排 10,200 行合成 CSV 的上传、完成、攻击链、自动调查和导出全流程。'],
 ['□','本次模型策略确定；解说只描述任务实际策略和可见的模型状态。'],
 ['□','至少准备一条多阶段链；路径节点可打开原始证据。'],
 ['□','至少准备一个本地 IOC 查询和一个攻击类型知识查询。'],
 ['□','API 密钥、用户个人信息和未授权数据不会出现在画面中。'],
 ['□','录屏后的 PDF/JSON 和视频文件有明确保存位置；清理工作区前已备份需要保留的材料。']
], [.55,6.45])
p('台词使用方式：引号内文字可以直接照读；括号外的操作说明不需要朗读。实际页面名称或状态与手册不一致时，以当前版本屏幕为准，先停下来修正操作，再继续录制。')

doc.save(OUT)
print(OUT)
