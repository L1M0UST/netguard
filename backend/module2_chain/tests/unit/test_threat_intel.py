"""Threat-intelligence enrichment tests (M2-F8, spec §10)."""

from __future__ import annotations

from backend.common.schemas.enums import IndicatorType
from backend.module2_chain.tests.conftest import make_event
from backend.module2_chain.threat_intel.base import (
    ThreatIntelResult,
    classify_indicator,
    host_of_url,
    normalise_indicator,
    refang,
)
from backend.module2_chain.threat_intel.local_provider import LocalThreatIntelProvider
from backend.module2_chain.threat_intel.service import (
    NoopThreatIntelProvider,
    ThreatIntelService,
)


def test_indicator_classification() -> None:
    assert classify_indicator("203.0.113.45") is IndicatorType.IP
    assert classify_indicator("2001:db8::1") is IndicatorType.IPV6
    assert classify_indicator("evil-c2.example.com") is IndicatorType.DOMAIN
    assert classify_indicator("hxxps://evil[.]example[.]com/payload") is IndicatorType.URL
    assert classify_indicator("CVE-2021-44228") is IndicatorType.CVE
    assert classify_indicator("44d88612fea8a8f36de82e1278abb02f") is IndicatorType.HASH
    assert classify_indicator("not an indicator") is None


def test_defanging_is_reversed() -> None:
    assert refang("hxxp://evil[.]example[.]com") == "http://evil.example.com"
    assert host_of_url("hxxps://evil[.]example[.]com:8443/x") == "evil.example.com"
    assert normalise_indicator("::ffff:10.0.0.8") == "10.0.0.8"


def test_local_provider_looks_up_every_indicator_type(config) -> None:
    provider = LocalThreatIntelProvider.from_config(config)
    health = provider.health()
    assert health["enabled"] is True
    assert health["tables"]

    ip_hit = provider.lookup("203.0.113.45")
    assert ip_hit is not None
    assert ip_hit.malicious is True
    assert "c2" in ip_hit.tags

    domain_hit = provider.lookup("evil-c2.example.com")
    assert domain_hit is not None
    assert domain_hit.indicator_type == "domain"

    cve_hit = provider.lookup("CVE-2021-44228")
    assert cve_hit is not None
    assert cve_hit.confidence > 0.9

    hash_hit = provider.lookup("44d88612fea8a8f36de82e1278abb02f")
    assert hash_hit is not None
    assert "malware" in hash_hit.tags

    assert provider.lookup("198.51.100.200") is None
    assert provider.lookup("") is None


def test_url_lookup_falls_back_to_the_embedded_domain(config) -> None:
    provider = LocalThreatIntelProvider.from_config(config)
    result = provider.lookup("https://evil-c2.example.com/beacon")
    assert result is not None
    assert result.indicator == "evil-c2.example.com"


def test_service_caches_and_reports_health(config) -> None:
    service = ThreatIntelService(config)
    first = service.enrich("203.0.113.45")
    second = service.enrich("203.0.113.45")
    assert first is not None and second is not None
    assert service.lookups == 1  # second call was served from the cache
    assert service.health()["hits"] == 1
    assert service.enrich("not-an-indicator") is None


def test_disabled_provider_is_branch_free(config) -> None:
    disabled = config.model_copy(
        update={
            "threat_intel": config.threat_intel.model_copy(
                update={"enabled": False, "provider": "noop"}
            )
        }
    )
    service = ThreatIntelService(disabled)
    assert isinstance(service.provider, NoopThreatIntelProvider)
    assert service.enrich("203.0.113.45") is None


def test_candidate_enrichment_attaches_evidence(config) -> None:
    from backend.module2_chain.attack.knowledge import load_knowledge_base
    from backend.module2_chain.correlation.engine import CorrelationEngine

    events = [
        make_event(
            "evt_1",
            src_ip="203.0.113.45",
            dst_ip="10.0.0.12",
            ioc_hits=["evil-c2.example.com"],
        )
    ]
    candidate = CorrelationEngine(
        config, knowledge=load_knowledge_base(config.attack_kb_path)
    ).correlate(events)[0]
    service = ThreatIntelService(config)
    results = service.enrich_candidate(candidate, events)
    indicators = {result.indicator for result in results}
    assert "203.0.113.45" in indicators
    assert "evil-c2.example.com" in indicators
    for result in results:
        if result.indicator in {"203.0.113.45", "evil-c2.example.com"}:
            assert result.evidence_event_ids == ["evt_1"]


def test_missing_threat_intel_directory_is_tolerated(make_config, tmp_path) -> None:
    config = make_config(tmp_path / "ws")
    empty_dir = tmp_path / "empty_intel"
    empty_dir.mkdir()
    service = ThreatIntelService(
        config.model_copy(
            update={
                "threat_intel": config.threat_intel.model_copy(
                    update={"path": str(empty_dir)}
                )
            }
        )
    )
    assert service.enrich("203.0.113.45") is None
    assert service.health()["enabled"] is True


def test_min_confidence_downgrades_weak_hits(config) -> None:
    class WeakProvider:
        name = "weak"
        enabled = True

        def lookup(self, indicator, indicator_type=None):
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=str(indicator_type or "ip"),
                malicious=True,
                confidence=0.1,
            )

        def lookup_many(self, indicators):
            return {indicator: self.lookup(indicator) for indicator in indicators}

        def health(self):
            return {"provider": self.name}

    service = ThreatIntelService(config, provider=WeakProvider())
    result = service.enrich("203.0.113.45")
    assert result is not None
    assert result.malicious is False
