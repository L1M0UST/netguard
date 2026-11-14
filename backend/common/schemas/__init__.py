"""Versioned shared data contracts.

Nothing in this package may import from ``backend.module2_chain`` (or any other
concrete module).  The dependency direction is always::

    concrete module  ->  backend.common.schemas
"""

from backend.common.schemas.alert import Alert
from backend.common.schemas.attack import (
    AttackCandidate,
    AttackChain,
    CandidateTechnique,
    ChainStage,
    LLMMeta,
    RiskFactor,
    RiskScore,
    ScoreSummary,
    ThreatIntelRef,
)
from backend.common.schemas.bundle import BundleFileRef, BundleManifest
from backend.common.schemas.entity import ThreatEntity
from backend.common.schemas.enums import (
    EntityRole,
    EntityType,
    IndicatorType,
    LLMCallStatus,
    MarkedFileState,
    MitigationKind,
    PipelineStage,
    Severity,
    TaskStatus,
    TechniqueSource,
)
from backend.common.schemas.profile import UNKNOWN_ATTRIBUTION, AttackerProfile
from backend.common.schemas.report import (
    EvidenceSummary,
    Mitigation,
    ReportAttackerSummary,
    ReportAttackEvent,
    ReportHighlight,
    ReportStatistics,
    ReportVictimSummary,
    RiskEventReport,
)
from backend.common.schemas.status import BatchProgress, TaskStatusRecord
from backend.common.schemas.suspicious_event import (
    BatchFileRef,
    Detection,
    EventCore,
    SuspiciousEvent,
    SuspiciousEventBatchManifest,
)
from backend.common.schemas.version import (
    ALERT_SCHEMA_VERSION,
    ATTACK_CHAIN_SCHEMA_VERSION,
    ATTACKER_PROFILE_SCHEMA_VERSION,
    MODULE2_BUNDLE_MANIFEST_SCHEMA_VERSION,
    RISK_EVENT_REPORT_SCHEMA_VERSION,
    SUPPORTED_SUSPICIOUS_EVENT_BATCH_VERSIONS,
    SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION,
    TASK_STATUS_SCHEMA_VERSION,
    THREAT_ENTITY_SCHEMA_VERSION,
)
from backend.common.schemas.workspace import (
    DONE_MARKER,
    MANIFEST_FILE,
    METRICS_FILE,
    PROCESSING_MARKER,
    READY_MARKER,
    TEMP_SUFFIX,
)

__all__ = [
    "ALERT_SCHEMA_VERSION",
    "ATTACKER_PROFILE_SCHEMA_VERSION",
    "ATTACK_CHAIN_SCHEMA_VERSION",
    "DONE_MARKER",
    "MANIFEST_FILE",
    "METRICS_FILE",
    "MODULE2_BUNDLE_MANIFEST_SCHEMA_VERSION",
    "PROCESSING_MARKER",
    "READY_MARKER",
    "RISK_EVENT_REPORT_SCHEMA_VERSION",
    "SUPPORTED_SUSPICIOUS_EVENT_BATCH_VERSIONS",
    "SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION",
    "TASK_STATUS_SCHEMA_VERSION",
    "TEMP_SUFFIX",
    "THREAT_ENTITY_SCHEMA_VERSION",
    "UNKNOWN_ATTRIBUTION",
    "Alert",
    "AttackCandidate",
    "AttackChain",
    "AttackerProfile",
    "BatchFileRef",
    "BatchProgress",
    "BundleFileRef",
    "BundleManifest",
    "CandidateTechnique",
    "ChainStage",
    "Detection",
    "EntityRole",
    "EntityType",
    "EventCore",
    "EvidenceSummary",
    "IndicatorType",
    "LLMCallStatus",
    "LLMMeta",
    "MarkedFileState",
    "Mitigation",
    "MitigationKind",
    "PipelineStage",
    "ReportAttackEvent",
    "ReportAttackerSummary",
    "ReportHighlight",
    "ReportStatistics",
    "ReportVictimSummary",
    "RiskEventReport",
    "RiskFactor",
    "RiskScore",
    "ScoreSummary",
    "Severity",
    "SuspiciousEvent",
    "SuspiciousEventBatchManifest",
    "TaskStatus",
    "TaskStatusRecord",
    "TechniqueSource",
    "ThreatEntity",
    "ThreatIntelRef",
]
