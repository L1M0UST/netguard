"""Asset criticality weights (configurable, optional)."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger

logger = get_logger("risk.assets")


class AssetInventory:
    """IP / CIDR -> criticality weight lookup.

    The inventory is optional: when the parquet file is missing every asset
    falls back to ``assets.default_weight`` so scoring stays deterministic.
    """

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.settings = config.assets
        self.default_weight = self.settings.default_weight
        self._exact: dict[str, float] = {}
        self._networks: list[tuple[Any, float]] = []
        self.loaded = False
        if self.settings.enabled:
            self._load(config.asset_path)

    def _load(self, path: Path) -> None:
        if not path.is_file():
            logger.warning(
                "asset inventory not found; using default asset weight",
                extra={"stage": "risk", "path": str(path)},
            )
            return
        try:
            import polars as pl

            frame = pl.read_parquet(path)
        except Exception as exc:  # pragma: no cover - polars raises many types
            logger.error(
                "failed to read the asset inventory",
                extra={"stage": "risk", "path": str(path), "error": str(exc)},
            )
            return
        columns = set(frame.columns)
        address_column = next(
            (name for name in ("ip", "address", "cidr", "asset", "indicator") if name in columns),
            None,
        )
        if address_column is None:
            logger.error(
                "asset inventory has no address column",
                extra={"stage": "risk", "path": str(path)},
            )
            return
        for row in frame.iter_rows(named=True):
            value = row.get(address_column)
            if not value:
                continue
            weight = self._weight_of_row(row)
            entry = str(value).strip()
            if "/" in entry:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    continue
                self._networks.append((network, weight))
            else:
                self._exact[entry.lower()] = weight
        self.loaded = True
        logger.info(
            "asset inventory loaded",
            extra={
                "stage": "risk",
                "path": str(path),
                "exact_assets": len(self._exact),
                "networks": len(self._networks),
            },
        )

    def _weight_of_row(self, row: dict[str, Any]) -> float:
        explicit = row.get("weight") or row.get("asset_weight")
        if explicit is not None:
            try:
                return max(0.1, float(explicit))
            except (TypeError, ValueError):
                pass
        criticality = str(row.get("criticality") or row.get("importance") or "").lower()
        weights = self.settings.criticality_weights
        return float(weights.get(criticality, self.default_weight))

    def weight_for(self, ip: str | None) -> float:
        if not ip:
            return self.default_weight
        key = ip.strip().lower()
        if key in self._exact:
            return self._exact[key]
        try:
            parsed = ipaddress.ip_address(key)
        except ValueError:
            return self.default_weight
        best = self.default_weight
        for network, weight in self._networks:
            if parsed in network and weight > best:
                best = weight
        return best

    def max_weight_for(self, ips: list[str]) -> float:
        if not ips:
            return self.default_weight
        return max(self.weight_for(ip) for ip in ips)

    def health(self) -> dict[str, Any]:
        return {
            "enabled": self.settings.enabled,
            "loaded": self.loaded,
            "exact_assets": len(self._exact),
            "networks": len(self._networks),
            "default_weight": self.default_weight,
        }
