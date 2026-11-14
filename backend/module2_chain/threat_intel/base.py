"""Provider abstraction and indicator helpers for threat intelligence."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from pydantic import Field

from backend.common.schemas.attack import ThreatIntelRef
from backend.common.schemas.enums import IndicatorType
from backend.module2_chain.app.logging import get_logger

logger = get_logger("threat_intel")

_CVE_PATTERN = re.compile(r"^cve-\d{4}-\d{4,7}$", re.IGNORECASE)
_HASH_PATTERN = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.IGNORECASE)
_URL_PATTERN = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9\-]{1,63}(?<!-)(\.(?!-)[a-z0-9\-]{1,63}(?<!-))+$",
    re.IGNORECASE,
)
_DEFANG_MAP = {
    "[.]": ".",
    "(.)": ".",
    "{.}": ".",
    "[dot]": ".",
    "hxxp": "http",
    "hxxps": "https",
    "[:]": ":",
    "[at]": "@",
}


class ThreatIntelResult(ThreatIntelRef):
    """Enrichment answer for a single indicator."""

    matched_indicators: list[str] = Field(default_factory=list)
    provider: str = "local"
    raw: dict[str, object] = Field(default_factory=dict)


@runtime_checkable
class ThreatIntelProvider(Protocol):
    """Interface every threat-intelligence backend must satisfy."""

    name: str
    enabled: bool

    def lookup(
        self, indicator: str, indicator_type: IndicatorType | str | None = None
    ) -> ThreatIntelResult | None:
        """Return enrichment for one indicator, or ``None`` when unknown."""

    def lookup_many(
        self, indicators: Iterable[str]
    ) -> dict[str, ThreatIntelResult | None]:
        """Batch lookup (default implementations may loop)."""

    def health(self) -> dict[str, object]:
        """Small self-description used by status files and metrics."""


def refang(value: str) -> str:
    """Undo common indicator defanging (``hxxp://evil[.]com``)."""

    result = value.strip()
    for source, target in _DEFANG_MAP.items():
        result = result.replace(source, target).replace(source.upper(), target)
    return result


def classify_indicator(value: str) -> IndicatorType | None:
    """Best-effort indicator classification used for lookups."""

    if not value:
        return None
    candidate = refang(value)
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return IndicatorType.IP if parsed.version == 4 else IndicatorType.IPV6
    if _CVE_PATTERN.match(candidate):
        return IndicatorType.CVE
    if _URL_PATTERN.match(candidate):
        return IndicatorType.URL
    if _HASH_PATTERN.match(candidate):
        return IndicatorType.HASH
    if _DOMAIN_PATTERN.match(candidate) and not candidate.replace(".", "").isdigit():
        return IndicatorType.DOMAIN
    return None


def normalise_indicator(value: str, indicator_type: IndicatorType | str | None = None) -> str:
    """Canonical form used as cache/lookup key."""

    candidate = refang(value).strip().lower()
    resolved_type = _coerce_indicator_type(indicator_type) or classify_indicator(candidate)
    if resolved_type in {IndicatorType.IP, IndicatorType.IPV6}:
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        # A v4-mapped IPv6 address is the same observable as its IPv4 form.
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            return str(parsed.ipv4_mapped)
        return str(parsed)
    if resolved_type is IndicatorType.URL:
        return candidate.rstrip("/")
    return candidate


def _coerce_indicator_type(value: IndicatorType | str | None) -> IndicatorType | None:
    if value is None or isinstance(value, IndicatorType):
        return value
    try:
        return IndicatorType(str(value).lower())
    except ValueError:
        return None


def host_of_url(value: str) -> str | None:
    """Extract the host part of a URL indicator."""

    match = re.match(r"^[a-z][a-z0-9+.\-]*://([^/?#]+)", refang(value), re.IGNORECASE)
    if not match:
        return None
    host = match.group(1)
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.split(":", 1)[0]
