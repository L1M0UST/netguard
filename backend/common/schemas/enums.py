"""Enumerations shared by every module."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher rank == more severe."""

        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class TaskStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PipelineStage(StrEnum):
    """Ordered stages of the Module 2 pipeline (see ``pipeline.py``)."""

    DISCOVERY = "discovery"
    CLAIM = "claim"
    VALIDATION = "validation"
    INGESTION = "ingestion"
    DEDUPLICATION = "deduplication"
    NORMALIZATION = "normalization"
    CORRELATION = "correlation"
    THREAT_INTEL = "threat_intel"
    TECHNIQUE_MAPPING = "technique_mapping"
    LLM_ANALYSIS = "llm_analysis"
    EVIDENCE_VALIDATION = "evidence_validation"
    CHAIN_BUILDING = "chain_building"
    RISK_SCORING = "risk_scoring"
    FINGERPRINTING = "fingerprinting"
    EVENT_DEDUPLICATION = "event_deduplication"
    PROFILING = "profiling"
    ENTITY_EXTRACTION = "entity_extraction"
    REPORT_GENERATION = "report_generation"
    BUNDLE_WRITE = "bundle_write"


class IndicatorType(StrEnum):
    IP = "ip"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    CVE = "cve"


class EntityType(StrEnum):
    IP = "ip"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    CVE = "cve"
    PORT = "port"
    PROTOCOL = "protocol"
    USERNAME = "username"
    HOSTNAME = "hostname"
    MALWARE = "malware"
    TOOL = "tool"
    TECHNIQUE = "technique"
    ASSET = "asset"


class EntityRole(StrEnum):
    ATTACKER = "attacker"
    VICTIM = "victim"
    TARGET = "target"
    INFRASTRUCTURE = "infrastructure"
    TOOL = "tool"
    INDICATOR = "indicator"
    UNKNOWN = "unknown"


class TechniqueSource(StrEnum):
    RULE = "rule"
    LLM = "llm"
    MERGED = "merged"
    FALLBACK = "fallback"


class MitigationKind(StrEnum):
    EVIDENCE_BASED = "evidence_based"
    GENERAL_RECOMMENDATION = "general_recommendation"


class LLMCallStatus(StrEnum):
    SUCCESS = "success"
    FALLBACK = "fallback"
    FALLBACK_USED = "fallback_used"
    TIMEOUT = "timeout"
    INVALID_JSON = "invalid_json"
    SCHEMA_ERROR = "schema_error"
    AUTH_ERROR = "auth_error"
    QUOTA_EXHAUSTED = "quota_exhausted"
    RATE_LIMITED = "rate_limited"
    PROVIDER_ERROR = "provider_error"
    NETWORK_ERROR = "network_error"
    DISABLED = "disabled"


class MarkedFileState(StrEnum):
    """Marker files used for the atomic file-delivery protocol."""

    READY = "READY"
    PROCESSING = "PROCESSING"
    DONE = "DONE"
