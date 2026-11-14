"""ThreatIntelService - enrichment façade used by the pipeline (M2-F8)."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable

from backend.common.schemas.attack import AttackCandidate
from backend.common.schemas.enums import IndicatorType
from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.threat_intel.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
    classify_indicator,
    normalise_indicator,
)
from backend.module2_chain.threat_intel.local_provider import LocalThreatIntelProvider

logger = get_logger("threat_intel.service")


class NoopThreatIntelProvider:
    """Explicitly disabled provider (keeps the pipeline branch-free)."""

    name = "noop"
    enabled = False

    def lookup(
        self, indicator: str, indicator_type: IndicatorType | str | None = None
    ) -> ThreatIntelResult | None:
        return None

    def lookup_many(
        self, indicators: Iterable[str]
    ) -> dict[str, ThreatIntelResult | None]:
        return dict.fromkeys(indicators)

    def health(self) -> dict[str, object]:
        return {"provider": self.name, "enabled": False}


class ThreatIntelService:
    """Cache and normalise all threat-intelligence lookups."""

    def __init__(
        self,
        config: AppConfig,
        *,
        provider: ThreatIntelProvider | None = None,
    ) -> None:
        self.config = config
        self.settings = config.threat_intel
        self.provider = provider or self._default_provider()
        self._cache: OrderedDict[tuple[str, str], ThreatIntelResult | None] = OrderedDict()
        self.cache_size = self.settings.cache_size
        self.lookups = 0
        self.hits = 0

    def _default_provider(self) -> ThreatIntelProvider:
        if not self.settings.enabled or self.settings.provider == "noop":
            return NoopThreatIntelProvider()
        if self.settings.remote.enabled:
            logger.warning(
                "remote threat-intel provider requested but not implemented; "
                "falling back to local",
                extra={"stage": "threat_intel"},
            )
        return LocalThreatIntelProvider(
            self.settings, base_dir=self.config.threat_intel_dir
        )

    # ------------------------------------------------------------------ #
    def enrich(self, indicator: str) -> ThreatIntelResult | None:
        """Look up one indicator (IP/domain/url/hash/CVE); cached."""

        if not indicator:
            return None
        indicator_type = classify_indicator(indicator)
        if indicator_type is None:
            return None
        key = (normalise_indicator(indicator, indicator_type), str(indicator_type))
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        self.lookups += 1
        result = self.provider.lookup(indicator, indicator_type)
        if result is not None and result.confidence >= self.settings.min_confidence:
            self.hits += 1
        elif result is not None:
            result = result.model_copy(update={"malicious": False})
        if self.cache_size > 0:
            self._cache[key] = result
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)
        return result

    def enrich_many(self, indicators: Iterable[str]) -> list[ThreatIntelResult]:
        results: list[ThreatIntelResult] = []
        seen: set[str] = set()
        for indicator in indicators:
            normalised = normalise_indicator(indicator) if indicator else ""
            if not normalised or normalised in seen:
                continue
            seen.add(normalised)
            result = self.enrich(indicator)
            if result is not None:
                results.append(result)
        return results

    # ------------------------------------------------------------------ #
    def candidate_indicators(
        self, candidate: AttackCandidate, events: list[SuspiciousEvent] | None = None
    ) -> dict[str, list[str]]:
        """Collect candidate indicators mapped to their evidence event ids."""

        evidence: dict[str, list[str]] = {}

        def _add(indicator: str | None, event_id: str | None) -> None:
            if not indicator:
                return
            key = normalise_indicator(indicator)
            if not key:
                return
            bucket = evidence.setdefault(key, [])
            if event_id and event_id not in bucket:
                bucket.append(event_id)

        if events:
            for event in events:
                if event.event.src_ip:
                    _add(event.event.src_ip, event.event.event_id)
                if event.event.dst_ip:
                    _add(event.event.dst_ip, event.event.event_id)
                for hit in event.detection.ioc_hits:
                    _add(hit, event.event.event_id)
        else:
            for ip in [*candidate.attacker_ips, *candidate.victim_ips]:
                _add(ip, None)
            for hit in candidate.ioc_hits:
                _add(hit, None)

        existing = {normalise_indicator(ref.indicator) for ref in candidate.threat_intel}
        for ref in candidate.threat_intel:
            evidence.setdefault(normalise_indicator(ref.indicator), [])
        return {key: value for key, value in evidence.items() if key not in existing}

    def enrich_candidate(
        self,
        candidate: AttackCandidate,
        events: list[SuspiciousEvent] | None = None,
        *,
        include_addresses: bool = True,
    ) -> list[ThreatIntelResult]:
        """Enrich one candidate and return the intelligence hits."""

        indicators = self.candidate_indicators(candidate, events)
        results: list[ThreatIntelResult] = []
        for indicator, evidence_ids in indicators.items():
            result = self.enrich(indicator)
            if result is None:
                continue
            if not include_addresses and result.indicator_type in {"ip", "ipv6"}:
                continue
            if evidence_ids:
                result = result.model_copy(update={"evidence_event_ids": list(evidence_ids)})
            results.append(result)
        return results

    def health(self) -> dict[str, object]:
        return {
            **self.provider.health(),
            "lookups": self.lookups,
            "hits": self.hits,
            "cache_entries": len(self._cache),
        }
