"""Module 2 internal models.

These models never cross the module boundary: Module 3 only ever reads the
public contracts in :mod:`backend.common.schemas`.
"""

from backend.module2_chain.schemas.internal import (
    CandidateAnalysis,
    ClaimOutcome,
    DeduplicationResult,
    EvidenceIssue,
    EvidenceValidationResult,
    IngestionResult,
    MetricsSnapshot,
    StageTiming,
    TaskOutcome,
    ValidationIssue,
    ValidationResult,
    WorkspaceTaskDescriptor,
)

__all__ = [
    "CandidateAnalysis",
    "ClaimOutcome",
    "DeduplicationResult",
    "EvidenceIssue",
    "EvidenceValidationResult",
    "IngestionResult",
    "MetricsSnapshot",
    "StageTiming",
    "TaskOutcome",
    "ValidationIssue",
    "ValidationResult",
    "WorkspaceTaskDescriptor",
]
