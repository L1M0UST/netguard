"""第二层传统机器学习（LightGBM）共享特征提取，训练与推理共用同一实现防漂移。

设计约束：
- 只依赖标准库 + numpy（推理走 LightGBM 原生 Booster，不引入 sklearn）；
- 输入为官方数据集 8 列原始字段（timestamp/user_agent/method/src_ip/dst_ip/url_path/request_body），
  与 M1 管线在 consume() 内 enrich 之后、重字段 pop 之前的事件字段对齐；
- 刻意不包含 rule_hits 特征：ML 层保持与规则层互补、独立验证，避免堆叠循环；
- 所有文本有界（截断），保证 1.1 万行级别的提取耗时在秒级。
"""
from __future__ import annotations

import hashlib
import html
import math
from urllib.parse import unquote_plus

# 类别 -> ml 伪规则名（bridge/labels.py RULE_LABELS 据此映射官方标签）
ML_RULE_BY_LABEL: dict[str, str] = {
    "SQL注入攻击": "ml_sql_injection",
    "XSS跨站脚本攻击": "ml_xss",
    "目录遍历攻击": "ml_path_traversal",
    "文件包含攻击": "ml_file_inclusion",
    "远程命令执行攻击": "ml_command_injection",
    "CSRF攻击": "ml_csrf",
    "Java反序列化漏洞利用攻击": "ml_java_deserialization",
    "文件上传攻击": "ml_file_upload",
}

# ML 命中的风险分：全部低于对应确定性规则分（90/85/90/75/70/75/65/60），体现证据质量差异
RISK_ML: dict[str, int] = {
    "ml_command_injection": 65,
    "ml_sql_injection": 60,
    "ml_java_deserialization": 65,
    "ml_file_inclusion": 55,
    "ml_file_upload": 55,
    "ml_path_traversal": 55,
    "ml_xss": 50,
    "ml_csrf": 45,
}

_TEXT_LIMIT = 2000


def _decode(value: object) -> str:
    """轻量解包一层 URL 编码与 HTML 实体；训练（xlsx 原文）与推理（事件原文）同口径。"""
    text = str(value or "")[:_TEXT_LIMIT]
    if not text:
        return ""
    decoded = unquote_plus(html.unescape(text))
    return decoded[:_TEXT_LIMIT]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _ratio(part: float, total: int) -> float:
    return part / total if total else 0.0


def _kw(text: str, *keywords: str) -> int:
    return sum(text.count(keyword) for keyword in keywords)


def _ip_is_private(value: object) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    parts = text.split(".")
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return False
    first = int(parts[0])
    return first == 10 or first == 127 or (first == 172 and parts[1].startswith(("1", "2"))) or (first == 192 and parts[1] == "168")


def FEATURE_NAMES() -> list[str]:
    """特征名清单（顺序即向量顺序）。meta.json 落盘该清单，加载时强校验一致。"""
    names: list[str] = []
    names += [f"method_{name}" for name in ("get", "post", "put", "delete", "other")]
    names += [
        "url_length", "url_slash_count", "url_digit_count", "url_digit_ratio",
        "url_special_count", "url_dotdot", "url_encoded_dotdot", "url_query_params",
        "url_entropy", "url_non_ascii_ratio", "url_long_token", "url_has_ip",
        "url_sensitive_path", "url_file_kw",
    ]
    names += [
        "body_length", "body_entropy", "body_special_ratio", "body_digit_ratio",
        "body_non_ascii_ratio", "body_newline_count",
        "body_kw_union_select", "body_kw_tautology", "body_kw_sleep_benchmark",
        "body_kw_information_schema", "body_kw_quote_comment",
        "body_kw_script_tags", "body_kw_cookie", "body_kw_traversal",
        "body_kw_wrapper", "body_kw_deserialization", "body_kw_upload",
        "body_kw_rce", "body_kw_csrf_admin", "body_kw_ssrf_ssti",
    ]
    names += [
        "ua_length", "ua_is_browser", "ua_scanner_kw", "ua_script_kw", "ua_empty", "ua_has_paren",
    ]
    names += ["src_private", "dst_private", "same_subnet24", "src_eq_dst"]
    names += ["hour_sin", "hour_cos"]
    names += ["total_text_length"]
    return names


def extract_features(row: dict) -> list[float]:
    """一行官方格式数据 -> 特征向量（顺序与 FEATURE_NAMES() 严格一致）。"""
    method = str(row.get("method") or "").strip().upper()
    url = _decode(row.get("url_path") or row.get("url") or "")
    body = _decode(row.get("request_body") or row.get("message") or row.get("payload") or "")
    ua = str(row.get("user_agent") or "").strip()[:_TEXT_LIMIT]
    ua_lower = ua.lower()

    features: list[float] = []
    # ---- method one-hot ----
    features += [
        1.0 if method == "GET" else 0.0,
        1.0 if method == "POST" else 0.0,
        1.0 if method == "PUT" else 0.0,
        1.0 if method == "DELETE" else 0.0,
        1.0 if method and method not in {"GET", "POST", "PUT", "DELETE"} else 0.0,
    ]

    # ---- url ----
    url_lower = url.lower()
    url_specials = sum(url.count(ch) for ch in ("<", ">", '"', "'", ";", "(", ")", "{", "}", "%", "$", "|", "&", "!"))
    digits = sum(ch.isdigit() for ch in url)
    segments = [seg for seg in url_lower.split("/") if seg]
    features += [
        float(len(url)),
        float(url.count("/")),
        float(digits),
        _ratio(digits, len(url)),
        float(url_specials),
        1.0 if ".." in url else 0.0,
        1.0 if "%2e%2e" in url_lower or "..%2f" in url_lower or "%2e%2e%2f" in url_lower else 0.0,
        float(url.count("=")),
        _entropy(url),
        _ratio(sum(ord(ch) > 127 for ch in url), len(url)),
        1.0 if any(len(seg) > 24 for seg in segments) else 0.0,
        1.0 if any(part and part.replace(".", "").isdigit() for part in url_lower.split("/")) else 0.0,
        1.0 if _kw(url_lower, ".env", ".git", "wp-admin", "wp-login", "phpmyadmin", "actuator", "server-status", "etc/passwd", "web.config", "/admin", "/console", "/manager") else 0.0,
        1.0 if _kw(url_lower, "file", "path", "include", "require", "download", "upload", "read", "template", "page=") else 0.0,
    ]

    # ---- body ----
    body_lower = body.lower()
    body_specials = sum(body.count(ch) for ch in ("<", ">", '"', "'", ";", "(", ")", "{", "}", "%", "$", "|", "&", "`", "!", "*", "+"))
    features += [
        float(len(body)),
        _entropy(body),
        _ratio(body_specials, len(body)),
        _ratio(sum(ch.isdigit() for ch in body), len(body)),
        _ratio(sum(ord(ch) > 127 for ch in body), len(body)),
        float(body.count("\n") + body.count("\r")),
        float(_kw(body_lower, "union select", "union all select", "union+select")),
        float(_kw(body_lower, "or 1=1", "' or '", '" or "', "or '1'", "1=1--", "and 1=1")),
        float(_kw(body_lower, "sleep(", "benchmark(", "waitfor delay", "pg_sleep")),
        float(_kw(body_lower, "information_schema", "sysobjects", "table_name", "column_name")),
        float(_kw(body_lower, "--", "#", "/*", "'''", '"""')),
        float(_kw(body_lower, "<script", "onerror=", "onload=", "javascript:", "alert(", "document.", "svg/onload", "<img", "<iframe")),
        float(_kw(body_lower, "document.cookie", "cookie", "location.href", "window.")),
        float(_kw(body_lower, "../", "..\\", "%2e%2e", "....//")),
        float(_kw(body_lower, "php://", "file://", "data://", "zip://", "phar://", "expect://", "data:text", "base64_decode", "eval(", "assert(")),
        float(_kw(body_lower, "rO0A", "aced", "readobject", "java.util", "java.lang", "serializable", "commons-collections", "xstream", "jndi:", "${jndi")),
        float(_kw(body_lower, "multipart", "filename=", "form-data", ".php", ".jsp", ".aspx", ".phtml", "content-disposition", "<?php", "<%")),
        float(_kw(body_lower, "whoami", "uname", "/bin/", "/etc/passwd", "cat ", "wget ", "curl ", "nc -", "bash", "sh -c", "powershell", "cmd.exe", "ping ", "certutil", "bitsadmin")),
        float(_kw(body_lower, "csrf", "token", "password", "admin", "role=", "permission", "confirm", "delete", "setting", "redirect", "recipient")),
        float(_kw(body_lower, "gopher://", "dict://", "ldap://", "{{", "}}", "%7b%7b", "jinja", "template", "ftps://", "telnet://")),
    ]

    # ---- user_agent ----
    features += [
        float(len(ua)),
        1.0 if "mozilla" in ua_lower else 0.0,
        float(_kw(ua_lower, "sqlmap", "nikto", "nmap", "masscan", "acunetix", "dirbuster", "gobuster", "wpscan", "nessus", "masscan")),
        float(_kw(ua_lower, "<script", "javascript", "python-requests", "curl/", "wget", "java/", "go-http", "libwww")),
        1.0 if not ua else 0.0,
        1.0 if "(" in ua else 0.0,
    ]

    # ---- network ----
    src = str(row.get("src_ip") or "")
    dst = str(row.get("dst_ip") or "")
    src_private = _ip_is_private(src)
    dst_private = _ip_is_private(dst)
    features += [
        1.0 if src_private else 0.0,
        1.0 if dst_private else 0.0,
        1.0 if src_private and dst_private and src.rsplit(".", 1)[0] == dst.rsplit(".", 1)[0] else 0.0,
        1.0 if src and src == dst else 0.0,
    ]

    # ---- timestamp hour（周期编码；缺失填 0 向量） ----
    hour = _parse_hour(row.get("timestamp"))
    features += [math.sin(2 * math.pi * hour / 24), math.cos(2 * math.pi * hour / 24)]

    # ---- combined ----
    features.append(float(len(url) + len(body)))
    return features


def _parse_hour(value: object) -> int:
    text = str(value or "")
    # 官方格式 "2026-08-09T14:23:05+00:00" / 常见变体；找不到时间返回 0（特征为 0 向量）
    marker = text.find("T")
    if marker < 0 or marker + 3 > len(text):
        return 0
    chunk = text[marker + 1:marker + 3]
    return int(chunk) if chunk.isdigit() else 0


def fingerprint_of_request(row: dict) -> str:
    """请求指纹（分组切分用）：去掉 timestamp/src_ip/dst_ip 后的请求组合哈希。"""
    parts = "|".join(str(row.get(key) or "") for key in ("method", "url_path", "request_body", "user_agent"))
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()
