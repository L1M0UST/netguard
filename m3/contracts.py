"""Shared public contracts for the v2.0 shared-workspace protocol.

M1/M2 producers should use the same field names when writing workspace files;
the legacy aliases remain optional so previously saved demo records can still
be displayed by M3.
"""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field

Severity = Literal['low', 'medium', 'high', 'critical']
TaskStatus = Literal['queued', 'running', 'completed', 'failed']

class FileRecord(BaseModel):
    file_id: str
    filename: str
    size: int = Field(ge=1)
    sha256: str = Field(pattern=r'^[a-f0-9]{64}$')

class CandidateAlert(BaseModel):
    schema_version: str = 'CandidateAlert.v1'
    alert_id: str
    title: str
    severity: Severity
    evidence: str
    source: str | None = None
    target: str | None = None
    mitre: str | None = None
    tactic: str | None = None
    technique: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    timestamp: datetime | None = None
    event_ids: list[str] = Field(default_factory=list)

class AttackChain(BaseModel):
    schema_version: str = 'AttackChain.v1'
    chain_id: str
    task_id: str
    severity: Severity
    nodes: list[str] = Field(min_length=1)
    evidence_ids: list[str]
    explanation: str
    stages: list[dict] = Field(default_factory=list)
    edges: list[tuple[str, str]] = Field(default_factory=list)

class AnalysisTask(BaseModel):
    task_id: str
    file_ids: list[str] = Field(min_length=1)
    query: str = ''
    filename: str | None = None
    status: TaskStatus
    progress: int = Field(ge=0, le=100)
    stage: str
    alerts: list[CandidateAlert] = Field(default_factory=list)
    chain: AttackChain | None = None
    created_at: datetime | None = None

class ProgressEvent(BaseModel):
    task_id: str
    status: TaskStatus
    progress: int = Field(ge=0, le=100)
    stage: str
    schema_version: str = 'Status.v1'

class TaskManifest(BaseModel):
    schema_version: str = 'TaskManifest.v1'
    task_id: str
    created_at: datetime | str
    source_files: list[dict] = Field(min_length=1)
    user_prompt: str = ''
    versions: dict[str, str] = Field(default_factory=dict)

class Status(BaseModel):
    schema_version: str = 'Status.v1'
    task_id: str
    state: Literal['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'DEGRADED']
    progress: int = Field(ge=0, le=100)
    message: str = ''

class ResultManifest(BaseModel):
    schema_version: str = 'ResultManifest.v1'
    task_id: str
    sha256: str = Field(pattern=r'^[a-f0-9]{64}$')

class ReportBundle(BaseModel):
    schema_version: str = 'ReportBundle.v1'
    task_id: str
    summary: str = ''
    recommended_actions: list[dict] = Field(default_factory=list)

class ChatRequest(BaseModel):
    task_id: str
    chain_id: str | None = None
    message: str = Field(min_length=1, max_length=4000)

class ChatDelta(BaseModel):
    text: str

class EvidenceEvent(BaseModel):
    items: list[CandidateAlert]
