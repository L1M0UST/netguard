"""Conservative text pattern extraction for threat entities.

Only unambiguous patterns are extracted (CVE ids, hashes, explicit ``user=``
fields, known tool names, domains).  Everything else stays as an IP/port/
protocol entity, which keeps the extractor free of speculation.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_HASH_PATTERN = re.compile(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz"
    r"|co|me|cc|su|onion|dev|cloud|shop|site)\b",
    re.IGNORECASE,
)
_USERNAME_PATTERN = re.compile(
    r"(?:user(?:name)?|account|login)\s*[=:]\s*['\"]?([A-Za-z0-9_.@\\\-]{2,64})",
    re.IGNORECASE,
)

#: Well known offensive tooling names (case-insensitive substring match).
_TOOL_NAMES: tuple[str, ...] = (
    "mimikatz",
    "psexec",
    "cobalt strike",
    "cobaltstrike",
    "meterpreter",
    "nmap",
    "masscan",
    "hydra",
    "sqlmap",
    "msfvenom",
    "metasploit",
    "bloodhound",
    "rubeus",
    "lazagne",
    "chisel",
    "ngrok",
    "empire",
    "sliver",
    "havoc",
    "brute ratel",
    "netcat",
    "socat",
)


def extract_cves(text: str) -> list[str]:
    if not text:
        return []
    return _unique(match.upper() for match in _CVE_PATTERN.findall(text))


def extract_hashes(text: str) -> list[str]:
    if not text:
        return []
    return _unique(match.lower() for match in _HASH_PATTERN.findall(text))


def extract_domains(text: str) -> list[str]:
    if not text:
        return []
    candidates: list[str] = []
    for raw_match in _DOMAIN_PATTERN.findall(text):
        cleaned = raw_match.strip(".").lower()
        try:
            ipaddress.ip_address(cleaned)
        except ValueError:
            candidates.append(cleaned)
    return _unique(candidates)


def extract_usernames(text: str) -> list[str]:
    if not text:
        return []
    return _unique(_USERNAME_PATTERN.findall(text))


def extract_tools(text: str) -> list[str]:
    if not text:
        return []
    lowered = text.lower()
    return _unique(name for name in _TOOL_NAMES if name in lowered)


def _unique(values: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        if value:
            seen.setdefault(str(value), None)
    return list(seen)
