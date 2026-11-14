"""官方攻击类型标签映射层（矛盾点#5）。

M1 的英文规则名 -> 赛题官方中文标签。数据集 ground truth 共 8 类攻击 + 正常访问；
本地垂域模型(cqsec)的候选集扩展到 16 类。本映射只依据 M1 规则命中做确定性判定，
不使用任何 ground truth 列；无规则命中的会话保持"待研判"，不虚构结论。
"""

from __future__ import annotations

# M1 规则名 -> 官方中文标签
RULE_LABELS: dict[str, str] = {
    "sql_injection": "SQL注入攻击",
    "xss": "XSS跨站脚本攻击",
    "path_traversal": "目录遍历攻击",
    "file_inclusion": "文件包含攻击",
    "command_injection": "远程命令执行攻击",
    "csrf": "CSRF攻击",
    "java_deserialization": "Java反序列化漏洞利用攻击",
    "file_upload": "文件上传攻击",
    "scanner": "扫描探测攻击",
    "multi_path_scan": "扫描探测攻击",
    "flow_scan": "扫描探测攻击",
}

# 多规则同时命中时的优先级：越靠前越具体（命令注入/反序列化 > 注入类 > 上传/遍历 > XSS/CSRF > 扫描）
RULE_PRIORITY: list[str] = [
    "command_injection",
    "java_deserialization",
    "sql_injection",
    "file_inclusion",
    "file_upload",
    "path_traversal",
    "xss",
    "csrf",
    "multi_path_scan",
    "scanner",
    "flow_scan",
]

LABEL_PENDING = "待研判"
LABEL_NORMAL = "正常访问"

# 本地垂域模型(cqsec)单条研判的 16 类候选标签，模型输出必须落在此集合内
CQSEC_LABELS: frozenset[str] = frozenset(
    {
        "SQL注入攻击", "XSS跨站脚本攻击", "目录遍历攻击", "文件包含攻击",
        "远程命令执行攻击", "CSRF攻击", "Java反序列化漏洞利用攻击", "文件上传攻击",
        "暴力破解攻击", "扫描探测攻击", "Webshell通信攻击", "C2回连攻击",
        "SSRF攻击", "XXE攻击", "SSTI攻击", "正常访问",
    }
)

# M1 风险等级 -> M3/Bundle 允许的 severity 枚举
SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


def label_for(rule_hits: list[str] | None, ioc_matches: list | None = None) -> str:
    """由规则命中推导官方中文标签；仅 IOC 命中或无命中时返回"待研判"。"""
    hits = [str(rule) for rule in (rule_hits or [])]
    for rule in RULE_PRIORITY:
        if rule in hits:
            return RULE_LABELS[rule]
    for hit in hits:  # 兜底：未知规则名按蛇形转空格展示，避免空标签
        if hit and hit not in RULE_LABELS:
            return LABEL_PENDING
    if ioc_matches:
        return LABEL_PENDING
    return LABEL_PENDING


def severity_for(risk_level: str | None) -> str:
    return SEVERITY_MAP.get(str(risk_level or "").lower(), "info")
