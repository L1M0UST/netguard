"""本地微调安全垂域模型 cqsec (Qwen3-4B QLoRA v3.2) 五大能力客户端。

接口协议：OpenAI Chat Completions 兼容（POST /v1/chat/completions）。
训练约束（必须遵守，见 模型相关文档.md 与 model/api/infer_client.py）：
- messages 只放 1 条 role="user"，指令 + 空行 + 输入数据 合并在一条消息里；
- 禁止 system 角色和多轮；
- temperature 0~0.3，max_tokens 300~600（研判 420 / 报告 600 / 画像 600 / 问答 500 / 总结 600）；
- 上下文 cutoff ~1024 token：事件/画像输入告警条数 ≤8/≤6 条；
- 服务 ≤4 并发；公网 api.limoust.xyz 必须带自定义 User-Agent。
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.request import Request, urlopen

CANDIDATE_LABELS = (
    "SQL注入攻击、XSS跨站脚本攻击、目录遍历攻击、文件包含攻击、远程命令执行攻击、CSRF攻击、"
    "Java反序列化漏洞利用攻击、文件上传攻击、暴力破解攻击、扫描探测攻击、Webshell通信攻击、"
    "C2回连攻击、SSRF攻击、XXE攻击、SSTI攻击、正常访问"
)

JUDGE_INSTRUCTION = (
    "你是网络安全态势感知中心的AI告警研判助手。请研判下列HTTP告警，"
    f"从候选类别【{CANDIDATE_LABELS}】中判定其类型，"
    "按“研判结论、判定依据、ATT&CK映射、处置建议”四段输出。"
)
EVENT_REPORT_INSTRUCTION = (
    "你是SOC事件研判专家。以下是从同一攻击事件聚合出的多条告警，请输出事件研判报告，"
    "包含【事件概述】【攻击阶段】【影响评估】【处置建议】四部分。"
)
PROFILE_INSTRUCTION = (
    "你是安全运营中心的攻击者画像分析师。请根据该攻击者的全部告警行为摘要，输出结构化画像，"
    "包含【活跃时间】【攻击能力】【目标偏好】【基础设施IOC】【意图研判】【处置建议】六部分。"
)
QA_INSTRUCTION = (
    "你是网络安全威胁情报专家。请基于MITRE ATT&CK等权威知识准确回答下列问题，"
    "答案需专业、简洁、可执行。"
)
OPS_SUMMARY_INSTRUCTION = (
    "你是安全运营经理。以下是一批告警的统计摘要，请输出面向管理层的运营总结，"
    "包含【总体态势】【重点风险】【处置优先级】【改进建议】四部分。"
)

_LABEL_RE = re.compile(r"攻击类型[:：]\s*([^\n；;，,。]+)")
_LABEL_FALLBACK_RE = re.compile(r"【研判结论】\s*([^\n；;，,。]+)")
_RISK_RE = re.compile(r"风险等级[:：]\s*([^\n；;，,。]+)")


class CqsecError(RuntimeError):
    """本地模型不可用或响应异常。"""


def _settings() -> tuple[str, str, int, str]:
    base = os.getenv("CQSEC_BASE_URL", "http://127.0.0.1:8008").rstrip("/")
    model = os.getenv("CQSEC_MODEL", "cqsec")
    timeout = int(os.getenv("CQSEC_TIMEOUT_SECONDS", "120"))
    ua = os.getenv("CQSEC_USER_AGENT", "cqsec-client/1.0")
    return base, model, timeout, ua


def chat(prompt: str, *, max_tokens: int = 600, temperature: float = 0.1,
         stream: bool = False) -> str:
    """单条 user 消息调用，返回 content 文本。失败抛 CqsecError。"""
    base, model, timeout, ua = _settings()
    payload = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": stream,
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {"Content-Type": "application/json"}
    if "127.0.0.1" not in base and "localhost" not in base:
        headers["User-Agent"] = ua  # 公网经 Cloudflare，缺自定义 UA 会被拦 (error 1010)
    try:
        with urlopen(Request(f"{base}/v1/chat/completions",
                             json.dumps(payload).encode("utf-8"), headers), timeout=timeout) as resp:
            result = json.load(resp)
    except Exception as exc:  # 网络/超时/HTTP 错误统一转业务异常
        raise CqsecError(f"cqsec 服务不可用: {exc}") from exc
    choice = (result.get("choices") or [{}])[0]
    content = (choice.get("message") or {}).get("content") or ""
    if not content.strip():
        raise CqsecError(f"cqsec 返回空内容 (finish_reason={choice.get('finish_reason')})")
    return content.strip()


def fmt_alert(alert: dict) -> str:
    """单条告警 7 字段定长格式（与训练数据对齐，字段行结构不可改）。"""
    return (
        f"时间: {alert.get('timestamp') or '未知'}\n"
        f"方法: {alert.get('method') or 'GET'}\n"
        f"源IP: {alert.get('src_ip') or '未知'}\n"
        f"目的IP: {alert.get('dst_ip') or '未知'}\n"
        f"User-Agent: {alert.get('user_agent') or '未知'}\n"
        f"URL路径: {alert.get('url_path') or '/'}\n"
        f"请求体: {alert.get('request_body') or '（空）'}"
    )


def judge(alert: dict) -> dict:
    """能力①：单条告警研判。返回 {label, risk, evidence, mitre, action, raw}。"""
    text = chat(f"{JUDGE_INSTRUCTION}\n\n{fmt_alert(alert)}", max_tokens=420)
    from bridge.labels import CQSEC_LABELS
    label = _LABEL_RE.search(text) or _LABEL_FALLBACK_RE.search(text)
    label_value = label.group(1).strip() if label else ""
    if label_value and label_value not in CQSEC_LABELS:
        # 候选集白名单过滤：模型输出越界时按子串回配，配不上则置空走人工复核
        matched = next((c for c in CQSEC_LABELS if c in label_value), "")
        label_value = matched
    risk = _RISK_RE.search(text)
    section = lambda name: next(  # noqa: E731
        (line.strip() for line in text.splitlines() if line.strip().startswith(f"【{name}】")), "")
    return {
        "label": label_value,
        "risk": risk.group(1).strip() if risk else "",
        "evidence": section("判定依据"),
        "mitre": section("ATT&CK映射"),
        "action": section("处置建议"),
        "raw": text,
    }


def _alert_lines(alerts: list[dict], limit: int) -> str:
    lines = []
    for alert in alerts[:limit]:
        stamp = str(alert.get("timestamp") or "")[5:16]
        lines.append(f"  {stamp}|{alert.get('method') or 'GET'}|"
                     f"{str(alert.get('url_path') or '/')[:60]}|"
                     f"{str(alert.get('request_body') or '（空）')[:50]}→{alert.get('attack_type') or '未研判'}")
    return "\n".join(lines)


def event_report(src_ip: str, dst_ip: str, lines: list[str],
                 first_seen: str, last_seen: str) -> str:
    """能力②：事件研判报告。

    lines 为调用方从证据行确定性构建的明细（时间|URL|载荷摘要→类型，≤8 行）——
    证据索引没有 method/request_body 独立列，缺什么字段就不写什么字段，不虚构。
    """
    body = (
        f"事件源IP: {src_ip}\n受害资产: {dst_ip}\n"
        f"时间跨度: {last_seen} 至 {first_seen}, 告警数: {len(lines[:8])}\n"
        "告警明细(时间|URL|载荷摘要→类型):\n" + "\n".join(lines[:8])
    )
    return chat(f"{EVENT_REPORT_INSTRUCTION}\n\n{body}", max_tokens=600)


def attacker_profile(attacker_ip: str, first_seen: str, last_seen: str, alerts: list[dict]) -> str:
    """能力③：攻击者画像（≤6 条行为摘要）。"""
    body = (
        f"攻击者IP: {attacker_ip}\n"
        f"活跃时间: {first_seen} 至 {last_seen}, 告警数: 见摘要\n"
        "行为摘要(时间|方法|URL|载荷):\n" + _alert_lines(alerts, 6)
    )
    return chat(f"{PROFILE_INSTRUCTION}\n\n{body}", max_tokens=600)


def intel_qa(question: str, context: str | None = None) -> str:
    """能力④：威胁情报问答（智能问答后端）。context 为任务证据摘要（可空）。"""
    body = question if not context else (
        "任务上下文（仅供参考，未经确证的事实，回答时注意区分）:\n"
        f"{context[:1200]}\n\n问题: {question}"
    )
    return chat(f"{QA_INSTRUCTION}\n\n{body}", max_tokens=500)


def ops_summary(stats_text: str) -> str:
    """能力⑤：运营总结（输入为批次统计摘要文本）。"""
    return chat(f"{OPS_SUMMARY_INSTRUCTION}\n\n{stats_text}\n请生成运营总结。", max_tokens=600)


def health() -> bool:
    """GET /v1/models 返回 200 即在线。"""
    base, _, timeout, ua = _settings()
    headers = {"User-Agent": ua} if "127.0.0.1" not in base and "localhost" not in base else {}
    try:
        with urlopen(Request(f"{base}/v1/models", headers=headers), timeout=min(timeout, 10)) as resp:
            return resp.status == 200
    except Exception:
        return False


def build_ops_stats_text(sev_counts: dict, events: int, chains: int, multistage: int,
                         metrics: dict, statistics: dict) -> str:
    """把加权后的真实分布拼成能力⑤输入（数字系统精确，要求原样引用；并说明链/事件关系）。"""
    attack_types = statistics.get("attack_type_counts") or {}
    type_text = "、".join(f"{k}({v})" for k, v in list(attack_types.items())[:4]) or "见告警明细"
    crit, high = sev_counts.get("critical", 0), sev_counts.get("high", 0)
    med, low = sev_counts.get("medium", 0), sev_counts.get("low", 0)
    attackers = statistics.get("attacker_count", metrics.get("attackers", "未知"))
    parts = [
        "批次告警统计(系统精确统计，生成时必须原样引用以下数字，禁止推算或修改):",
        f"接入原始 {metrics.get('raw_count', '未知')}，可疑事件 {metrics.get('suspicious_count', '未知')}，"
        f"确认攻击事件 {events}，攻击链 {chains}（其中多阶段链 {multistage}），"
        f"攻击者 {attackers} 个",
        f"风险分级：严重 {crit}、高危 {high}、中危 {med}、低危 {low}（高危及以上合计 {crit + high}）",
        f"类型分布：{type_text}",
        "口径说明：单事件会话各自独立成链时，攻击链数会接近攻击事件数，属正常现象，"
        "不要把这两个数当作两个彼此独立的结论；请依据'高危及以上数量'与'多阶段链数量'判断总体风险，"
        "严禁输出'高危告警0条却称风险严重'这类自相矛盾的表述。",
    ]
    return "\n".join(parts)


if __name__ == "__main__":
    print("health:", health())
    print(judge({"timestamp": "2025-11-02 03:40:56", "method": "POST", "src_ip": "45.61.10.9",
                 "dst_ip": "10.60.33.18", "user_agent": "python-requests/2.31",
                 "url_path": "/gate77.php", "request_body": "host=c2server512.cn&id=9af3c2e18b77d001&s=60"}))
