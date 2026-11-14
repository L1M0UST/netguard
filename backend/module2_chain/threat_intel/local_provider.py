"""Local parquet threat-intelligence provider (no network access)."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import polars as pl

from backend.common.schemas.enums import IndicatorType
from backend.module2_chain.app.config import AppConfig, ThreatIntelSettings
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.threat_intel.base import (
    ThreatIntelResult,
    classify_indicator,
    host_of_url,
    normalise_indicator,
)

logger = get_logger("threat_intel.local")

#: Column aliases tolerated in the local databases.
_INDICATOR_COLUMNS = ("indicator", "ioc", "value", "ip", "domain", "hash", "cve")
_REQUIRED_DEFAULTS: dict[str, Any] = {
    "malicious": True,
    "confidence": 0.5,
    "source": "local",
    "tags": (),
    "description": None,
}


class LocalThreatIntelProvider:
    """Loads ``data/threat_intel/*.parquet`` into memory and serves lookups."""

    name = "local"

    def __init__(self, settings: ThreatIntelSettings, *, base_dir: Path) -> None:
        self.settings = settings
        self.base_dir = Path(base_dir)
        self.enabled = settings.enabled and settings.provider == "local"
        self._tables: dict[IndicatorType, dict[str, ThreatIntelResult]] = {}
        self._load_errors: list[str] = []
        if self.enabled:
            self._load()

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #
    @classmethod
    def from_config(cls, config: AppConfig) -> LocalThreatIntelProvider:
        return cls(config.threat_intel, base_dir=config.threat_intel_dir)

    def _file_map(self) -> dict[IndicatorType, str]:
        files = self.settings.files
        return {
            IndicatorType.IP: files.ip,
            IndicatorType.DOMAIN: files.domain,
            IndicatorType.HASH: files.hash,
            IndicatorType.CVE: files.cve,
        }

    def _load(self) -> None:
        for indicator_type, file_name in self._file_map().items():
            path = self.base_dir / file_name
            if not path.is_file():
                logger.warning(
                    "local threat-intel file not found (skipping)",
                    extra={"stage": "threat_intel", "path": str(path)},
                )
                continue
            try:
                frame = pl.read_parquet(path)
            except Exception as exc:  # pragma: no cover - polars raises many types
                self._load_errors.append(f"{file_name}: {exc}")
                logger.error(
                    "failed to read local threat-intel file",
                    extra={"stage": "threat_intel", "path": str(path), "error": str(exc)},
                )
                continue
            self._tables[indicator_type] = self._index(frame, indicator_type)
            logger.info(
                "loaded local threat-intel file",
                extra={
                    "stage": "threat_intel",
                    "path": str(path),
                    "indicators": len(self._tables[indicator_type]),
                    "indicator_type": str(indicator_type),
                },
            )

    def _index(
        self, frame: pl.DataFrame, indicator_type: IndicatorType
    ) -> dict[str, ThreatIntelResult]:
        columns = set(frame.columns)
        indicator_column = next(
            (name for name in _INDICATOR_COLUMNS if name in columns), None
        )
        if indicator_column is None:
            self._load_errors.append(f"{indicator_type}: no indicator column")
            logger.error(
                "threat-intel file has no indicator column",
                extra={"stage": "threat_intel", "indicator_type": str(indicator_type)},
            )
            return {}

        table: dict[str, ThreatIntelResult] = {}
        for row in frame.iter_rows(named=True):
            raw_indicator = row.get(indicator_column)
            if not raw_indicator:
                continue
            value = str(raw_indicator)
            key = normalise_indicator(value, indicator_type)
            table.setdefault(
                key,
                ThreatIntelResult(
                    indicator=value,
                    indicator_type=str(indicator_type),
                    malicious=bool(row.get("malicious", _REQUIRED_DEFAULTS["malicious"])),
                    confidence=_as_float(
                        row.get("confidence"), float(_REQUIRED_DEFAULTS["confidence"])
                    ),
                    source=str(row.get("source") or _REQUIRED_DEFAULTS["source"]),
                    tags=_as_tags(row.get("tags")),
                    first_seen=_as_datetime(row.get("first_seen")),
                    last_seen=_as_datetime(row.get("last_seen")),
                    description=_as_text(row.get("description")),
                    matched_indicators=[key],
                    provider=self.name,
                ),
            )
        return table

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #
    def lookup(
        self, indicator: str, indicator_type: IndicatorType | str | None = None
    ) -> ThreatIntelResult | None:
        if not self.enabled or not indicator:
            return None
        resolved_type = _coerce_type(indicator_type) or classify_indicator(indicator)
        if resolved_type is None:
            return None
        key = normalise_indicator(indicator, resolved_type)
        found = self._tables.get(resolved_type, {}).get(key)
        if found is not None:
            return found
        # URL lookups fall back to the embedded host (domain/IP tables).
        if resolved_type is IndicatorType.URL:
            host = host_of_url(indicator)
            if host:
                host_type = classify_indicator(host)
                if host_type is not None:
                    return self._tables.get(host_type, {}).get(
                        normalise_indicator(host, host_type)
                    )
        return None

    def lookup_many(
        self, indicators: Iterable[str]
    ) -> dict[str, ThreatIntelResult | None]:
        return {indicator: self.lookup(indicator) for indicator in indicators}

    def health(self) -> dict[str, object]:
        return {
            "provider": self.name,
            "enabled": self.enabled,
            "base_dir": str(self.base_dir),
            "tables": {
                str(indicator_type): len(table)
                for indicator_type, table in self._tables.items()
            },
            "errors": list(self._load_errors),
        }


def _coerce_type(value: IndicatorType | str | None) -> IndicatorType | None:
    if value is None:
        return None
    if isinstance(value, IndicatorType):
        return value
    try:
        return IndicatorType(str(value).lower())
    except ValueError:
        return None


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def _as_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None
