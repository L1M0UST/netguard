"""Threat-intelligence enrichment.

The default provider reads **local** parquet databases; no runtime HTTP call is
required.  A remote provider exists behind an explicit feature flag and is off
by default.
"""

from backend.module2_chain.threat_intel.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
    classify_indicator,
    refang,
)
from backend.module2_chain.threat_intel.local_provider import LocalThreatIntelProvider
from backend.module2_chain.threat_intel.service import ThreatIntelService

__all__ = [
    "LocalThreatIntelProvider",
    "ThreatIntelProvider",
    "ThreatIntelResult",
    "ThreatIntelService",
    "classify_indicator",
    "refang",
]
