# -*- coding: utf-8 -*-
"""NetGuard 全功能数据处理流程图（pymupdf 矢量绘制 → PNG）。

运行: .venv/Scripts/python.exe scripts/draw_pipeline_flow.py
输出: docs/全功能流程图.png / docs/全功能流程图.pdf
口径与 docs/数据处理全流程图.md 的 13 步一致（评分权重随 11-15 重构为六因子，图内不写具体权重）。
"""
import fitz
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_PNG = ROOT / "docs" / "全功能流程图.png"
OUT_PDF = ROOT / "docs" / "全功能流程图.pdf"

# ---------- 字体 ----------
for cand in ("C:/Windows/Fonts/simhei.ttf", "C:/Windows/Fonts/Deng.ttf",
             "C:/Windows/Fonts/msyh.ttc"):
    if Path(cand).exists():
        FONT_PATH = cand
        break
else:
    raise SystemExit("未找到可用的中文字体")
FONT = fitz.Font(fontfile=FONT_PATH)

W, H = 1480, 1880
NAVY = (0x0B / 255, 0x12 / 255, 0x20 / 255)
BLUE = (0x1D / 255, 0x4E / 255, 0xD8 / 255)
GRAY = (0x64 / 255, 0x74 / 255, 0x8B / 255)


def text_w(s, size):
    return FONT.text_length(s, fontsize=size)


def wrap(s, size, maxw):
    lines, cur = [], ""
    for ch in s:
        if text_w(cur + ch, size) <= maxw or not cur:
            cur += ch
        else:
            lines.append(cur)
            cur = ch
    if cur:
        lines.append(cur)
    return lines


doc = fitz.open()
page = doc.new_page(width=W, height=H)
pw = page

# 页面底色
pw.draw_rect(fitz.Rect(0, 0, W, H), color=None, fill=(1, 1, 1))


def _c(c):
    """颜色归一化：任一分量 >1 视为 0-255 整数色，整体除 255。"""
    if any(x > 1 for x in c):
        return [x / 255 for x in c]
    return list(c)


def put(x, y, s, size=13, color=NAVY, bold_w=None):
    """在 (x, y) 为文本顶部写一行；y 为该行 top。返回行高。"""
    tw = fitz.TextWriter(page.rect)
    tw.append(fitz.Point(x, y + size * 0.9), s, font=FONT, fontsize=size)
    tw.write_text(page, color=_c(color))
    return size * 1.32


def put_centered(cx, y, s, size=13, color=NAVY):
    x = cx - text_w(s, size) / 2
    return put(x, y, s, size, color)


def box(r, fill, border, width=1.4, radius=10):
    """圆角矩形：pymupdf draw_rect 支持 radius 参数(0-0.5)。"""
    pw.draw_rect(r, color=_c(border), fill=_c(fill),
                 radius=min(0.5, radius / min(r.width, r.height)), width=width)


def arrow(x1, y1, x2, y2, color=GRAY, dashed=False, width=1.6, head=7):
    color = _c(color)
    if dashed:
        pw.draw_line(fitz.Point(x1, y1), fitz.Point(x2, y2), color=color, width=width,
                     dashes="[3 3] 0")
    else:
        pw.draw_line(fitz.Point(x1, y1), fitz.Point(x2, y2), color=color, width=width)
    import math
    ang = math.atan2(y2 - y1, x2 - x1)
    for da in (2.6, -2.6):
        pw.draw_line(fitz.Point(x2, y2),
                     fitz.Point(x2 - head * math.cos(ang + da), y2 - head * math.sin(ang + da)),
                     color=color, width=width)


# ---------- 标题 ----------
put_centered(W / 2, 26, "NetGuard 数据处理全流程图", 30, NAVY)
put_centered(W / 2, 66, "多模态上传 → 降噪检测 → 级联研判 → 关联成链 → 反幻觉校验 → 态势呈现", 14, GRAY)

# ---------- 主流程 13 步 ----------
# (编号, 名称, 技术行, 样例行, 阶段色系key)
STAGES = [
    ("①", "文件上传（多模态接入）", "M3 Web 上传 CSV / XLSX / PCAP / PCAPNG / JSON / JSONL，≤2GB；建任务并选研判策略",
     "样例：赛题2.xlsx 11,000 行 · 创建 manifest.json 投递 m3/READY", "m1"),
    ("②", "解析与 Schema 映射", "魔数判型 → 中英文列别名表 + 前 200 行类型画像 → 未知字段 LLM 兜底映射(置信≥0.85) → 冻结缓存",
     "样例：原始行 → 标准化事件 {src_ip, dst_ip, url_path, request_body…}", "m1"),
    ("③", "提示注入检测（自防）", "LogInject 式指令模式正则（ignore previous instructions 等）；命中片段替换为「注入内容已拦截」",
     "样例：恶意载荷 → LLM 只收到脱敏文本，metrics.prompt_injection_blocked 计数", "m1"),
    ("④", "清洗与降噪", "空记录丢弃 · 内容指纹+60s 时间桶去重 · 白名单/可信网段过滤",
     "样例：11,000 行 → 10,955 个会话", "m1"),
    ("⑤", "L1 规则 + IOC 匹配", "10 类正则签名(最多 2 轮 URL 解码+base64) · IOC 本地库(Spamhaus/OpenPhish/手工 1712+ 条)",
     "样例：\"or 1=1\" → sql_injection · 风险分 85(high)", "m1"),
    ("⑥", "L2 会话聚合与加权评分", "五元组+300s 空闲窗聚合 · 扫描检测 · 评分=max规则分+频率+源活跃度+资产重要性(封顶100)",
     "样例：10,955 会话 → 6,631 个可疑会话(≥45 分入 L3)", "m1"),
    ("⑦", "L3 级联语义研判 ★", "本地 cqsec(Qwen3-4B 微调)先判 → 置信<0.5 或失败才升级云端复核；候选 ≤1% 预算",
     "样例：本地命中 SQL注入攻击·高 → malicious 0.9 · 路由统计写 status.metrics.cascade", "m1"),
    ("⑧", "契约转换 bridge（自研）", "会话按 related_event_ids 展开为事件级 · 规则→官方中文标签 · evidence 索引(Parquet) · IOC 导出",
     "样例：6,631 会话 → 6,675 事件（防 Defender 明文隔离）", "bridge"),
    ("⑨", "M2 关联与攻击链", "两两加权(时间/攻击者/受害者/行为/IOC)+并查集 · ATT&CK 知识库(34技术/14战术) · LLM 候选研判(Top-60 预算)",
     "样例：6,675 事件 → 6,577 攻击链（预算内 60 条 LLM 增强）", "m2"),
    ("⑩", "反幻觉证据校验", "LLM 引用的 evidence_event_ids 必须真实存在 · 战术技术须在候选集内 · 幻觉扣分",
     "样例：evidence_validation{valid:true, hallucination_detected:false}", "m2"),
    ("⑪", "风险评分与置信度卡 ★", "六因子加权(内容+证据)×100 + M1 初筛严重度融合(取高) · 五档等级 · 置信度卡片(因子/惩罚/理由)",
     "样例：综合风险分 78/100 · 「LLM 结论反幻觉校验通过（有效证据 3 条）」", "m2"),
    ("⑫", "bundle 组装与原子投递", "AttackChainBundle.v1 自校验(引用闭合/五键 versions) · sha256 manifest · 原子 rename",
     "样例：6577 告警/6577 链/889 画像 → m2/READY/<task>/bundle.json", "bundle"),
    ("⑬", "M3 前端呈现与交互", "SSE 0.25s 进度轮询(Status.v1) · 统计类问答确定性直答(与页面同源零幻觉)",
     "样例：问\"高危多少条\" → 4,131（high+critical，同源数据）", "m3"),
]

PHASES = {  # 阶段分组（右侧竖排标签）
    "m1": ("M1 · 接入·降噪·检测·研判", (0xEF / 255, 0xF6 / 255, 0xFF / 255), BLUE),
    "bridge": ("桥接层 · 契约转换", (0xF5 / 255, 0xF3 / 255, 0xFF / 255), (0x7C / 255, 0x3A / 255, 0xED / 255)),
    "m2": ("M2 · 关联·研判·评分", (0xF0 / 255, 0xFD / 255, 0xF4 / 255), (0x05 / 255, 0x96 / 255, 0x69 / 255)),
    "bundle": ("组装层 · bundle", (0xFF / 255, 0xF7 / 255, 0xED / 255), (0xD9 / 255, 0x77 / 255, 0x06 / 255)),
    "m3": ("呈现层 · M3 BFF", (0xF8 / 255, 0xFA / 255, 0xFC / 255), (0x47 / 255, 0x55 / 255, 0x69 / 255)),
}

X0, X1 = 150, 1090  # 主框横向范围
y = 108
BOXY, GAP, BOXH = 16, 26, 0
tops = []
fills = {k: tuple(c / 255 for c in v) for k, v in
         {"m1": (0xEF, 0xF6, 0xFF), "bridge": (0xF5, 0xF3, 0xFF),
          "m2": (0xF0, 0xFD, 0xF4), "bundle": (0xFF, 0xF7, 0xED),
          "m3": (0xF8, 0xFA, 0xFC)}.items()}
borders = {k: tuple(c / 255 for c in v) for k, v in
           {"m1": (0x1D, 0x4E, 0xD8), "bridge": (0x7C, 0x3A, 0xED),
            "m2": (0x05, 0x96, 0x69), "bundle": (0xD9, 0x77, 0x06),
            "m3": (0x47, 0x55, 0x69)}.items()}

for i, (num, name, tech, sample, ph) in enumerate(STAGES):
    box_h = 86
    r = fitz.Rect(X0, y, X1, y + box_h)
    box(r, fills[ph], borders[ph], width=1.5)
    # 编号徽章
    c = fitz.Rect(X0 + 14, y + 22, X0 + 58, y + 66)
    pw.draw_circle(fitz.Point((c.x0 + c.x1) / 2, (c.y0 + c.y1) / 2), 21,
                   color=borders[ph], fill=borders[ph])
    put_centered((c.x0 + c.x1) / 2, y + 32, num, 17, (1, 1, 1))
    # 名称 + 技术 + 样例
    tx = X0 + 74
    put(tx, y + 12, name, 16, borders[ph] if ph != "m1" else (0x1E, 0x3A, 0x8A))
    put(tx, y + 36, tech, 12.2, (0x33, 0x41, 0x55))
    put(tx, y + 60, sample, 11.2, GRAY)
    tops.append(y)
    y += box_h + GAP
    if i < len(STAGES) - 1:
        arrow((X0 + X1) / 2, y - GAP + 1, (X0 + X1) / 2, y - 1, color=borders[ph], width=1.8)

# ---------- 左侧产物轨 ----------
put(20, 100, "数据产物轨", 13, GRAY)
ARTIFACTS = [
    (0, "manifest.json\nm3/READY/<task>/"),
    (6, "m1/ready/batch-<t>/\nbatch.json + READY"),
    (7, "04_m2_inbox/<task>/\nevents.parquet\n+evidence.parquet"),
    (10, "m2/output/<task>/\nparquet 结果集"),
    (11, "m2/READY/<t>/\nbundle.json"),
    (12, "m3/data/state\n(M3 轮询展示)"),
]
for idx, label in ARTIFACTS:
    yy = tops[idx] + 14
    lines = label.split("\n")
    hh = 16 + 15 * len(lines)
    box(fitz.Rect(12, yy, 132, yy + hh), (0xF1, 0xF5, 0xF9), (0xCB, 0xD5, 0xE1), width=1)
    ly = yy + 6
    for ln in lines:
        ly += put(20, ly, ln, 9.8, (0x47, 0x55, 0x69))
    arrow(133, yy + hh / 2, X0 - 1, tops[idx] + 43, color=(0x94, 0xA3, 0xB8), dashed=True, width=1.1, head=5)

# ---------- 右侧模型分工 ----------
put(1120, 100, "模型分工轨", 13, GRAY)
models = [
    (6, "本地 cqsec\nQwen3-4B QLoRA 微调\n127.0.0.1:8008 ≤4并发\n①研判第一档 ②报告\n③画像 ④问答 ⑤总结", (0xFE, 0xF2, 0xF2), (0xDC, 0x26, 0x26)),
    (8, "云端三路兜底链\nOpenCode Go →\nCommandCode → DeepSeek\n⑦L3升级档\n⑨候选研判 Top-60", (0xFF, 0xFB, 0xEB), (0xD9, 0x77, 0x06)),
]
for idx, label, fl, bd in models:
    yy = tops[idx] + 6
    lines = label.split("\n")
    hh = 16 + 15.5 * len(lines)
    box(fitz.Rect(1124, yy, 1352, yy + hh), fl, bd, width=1.2)
    ly = yy + 6
    for ln in lines:
        ly += put(1134, ly, ln, 10.2, (0x7F, 0x1D, 0x1D) if bd[0] > 0.8 else (0x92, 0x40, 0x0A))
    arrow(1123, yy + hh / 2, X1 + 1, tops[idx] + 43, color=(0x94, 0xA3, 0xB8), dashed=True, width=1.1, head=5)

# ---------- 底部：前端功能一览 ----------
y += 26
put_centered(W / 2 - 30, y, "┄ ⑬ M3 前端功能一览（一条链路产出，全页面同源）┄", 14, GRAY)
y += 30
FEATS = [
    ("态势总览", "数据漏斗·等级占比\n资产双榜单·指标 chips"),
    ("告警中心", "筛选/已读/CSV 导出\n告警详情弹窗"),
    ("攻击链分析", "路径图·画像·处置\n证据四标签页"),
    ("证据置信度卡", "因子条形图·反幻觉\n结论·惩罚项"),
    ("一键自动调查", "SSE 流式逐链轨迹\n⚡ 演示按钮"),
    ("威胁情报查询", "本地库→在线→信誉库\n三级管线 + AI 深度分析"),
    ("AI 问答抽屉", "统计直答+知识问答\n快捷问题 chips"),
    ("报告导出", "PDF 七章节\n（中文·含方法与版本）"),
]
fw = 160
fx0 = (W - (fw + 10) * 8 + 10) / 2
for i, (t, d) in enumerate(FEATS):
    fx = fx0 + i * (fw + 10)
    box(fitz.Rect(fx, y, fx + fw, y + 64), (1, 1, 1), (0x94, 0xA3, 0xB8), width=1.1)
    put_centered(fx + fw / 2, y + 8, t, 12.5, (0x1E, 0x3A, 0x8A))
    ly = y + 28
    for ln in d.split("\n"):
        ly += put_centered(fx + fw / 2, ly, ln, 9.8, (0x47, 0x55, 0x69))

y += 84
put_centered(W / 2, y, "规则与 IOC 始终参与检测；三种研判策略仅改变 L3 / M2 的模型用法", 12, GRAY)
ly = y + 22
for s in ("local 仅本地模型 = 数据不出本机（M2 关闭云端，需 cqsec 在线）",
          "cloud 仅互联网模型 = 级联关闭，候选全部走云端",
          "hybrid（默认）= 本地初判，置信 < 0.5 才升级云端复核"):
    ly += put_centered(W / 2, ly, s, 11.5, (0x47, 0x55, 0x69))

OUT_PDF.write_bytes(doc.tobytes())
pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
OUT_PNG.write_bytes(pix.tobytes("png"))
print("OK", OUT_PNG, OUT_PNG.stat().st_size)
