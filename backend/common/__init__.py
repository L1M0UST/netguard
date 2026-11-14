"""Shared artefacts used by every module.

``backend.common.schemas`` holds the versioned data contracts that Module 1,
Module 2 and Module 3 agree on.  Schemas are *additive only* inside a major
version.
"""

from backend.common.schemas import (
    ATTACK_CHAIN_SCHEMA_VERSION,
    SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION,
    Alert,
    AttackCandidate,
    AttackChain,
    AttackerProfile,
    RiskEventReport,
    SuspiciousEvent,
    SuspiciousEventBatchManifest,
    TaskStatusRecord,
    ThreatEntity,
)

__all__ = [
    "ATTACK_CHAIN_SCHEMA_VERSION",
    "SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION",
    "Alert",
    "AttackCandidate",
    "AttackChain",
    "AttackerProfile",
    "RiskEventReport",
    "SuspiciousEvent",
    "SuspiciousEventBatchManifest",
    "TaskStatusRecord",
    "ThreatEntity",
]
