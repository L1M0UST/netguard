"""Central configuration.

Precedence (highest first):

1. explicit environment variables (``LLM_PROVIDER``, ``DEEPSEEK_API_KEY`` ...)
2. ``.env`` file (never committed)
3. ``config.yaml``
4. model defaults

Every business threshold lives here or in ``config.yaml`` - the pipeline code
must not hard-code tunables.  Secrets are stored as ``SecretStr`` so they can
never leak into logs or ``model_dump()`` output.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, TypeAdapter, ValidationError

DEFAULT_CONFIG_ENV_VAR = "M2_CONFIG_FILE"
DEFAULT_DOTENV_ENV_VAR = "M2_DOTENV_FILE"


class ConfigError(RuntimeError):
    """Raised when configuration is missing or invalid."""


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


class AppSettings(_Base):
    name: str = "module2-chain"
    environment: Literal["dev", "test", "prod"] = "dev"
    fail_fast: bool = False
    max_events_per_task: int = Field(default=2_000_000, ge=1)
    timezone: str = "UTC"


class ClaimSettings(_Base):
    enabled: bool = True
    stale_after_seconds: float = Field(default=900.0, gt=0)
    heartbeat_seconds: float = Field(default=30.0, gt=0)
    owner: str | None = None


class ScanSettings(_Base):
    interval_seconds: float = Field(default=10.0, gt=0)
    max_tasks_per_scan: int = Field(default=4, ge=1)
    process_all_pending: bool = False


class AtomicWriteSettings(_Base):
    fsync: bool = True
    checksum_algorithm: Literal["sha256"] = "sha256"


class WorkspaceSettings(_Base):
    root: str = "workspace"
    inbox_subdir: str = "04_m2_inbox"
    output_subdir: str = "05_m2_output"
    status_subdir: str = "06_status/m2"
    ready_marker: str = "READY"
    processing_marker: str = "PROCESSING"
    done_marker: str = "DONE"
    failed_marker: str = "FAILED"
    manifest_name: str = "manifest.json"
    temp_suffix: str = ".tmp"
    auto_create: bool = True
    claim: ClaimSettings = Field(default_factory=ClaimSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    atomic_write: AtomicWriteSettings = Field(default_factory=AtomicWriteSettings)

    def inbox_path(self, project_root: Path) -> Path:
        return _resolve(project_root, self.root) / self.inbox_subdir

    def output_path(self, project_root: Path) -> Path:
        return _resolve(project_root, self.root) / self.output_subdir

    def status_path(self, project_root: Path) -> Path:
        return _resolve(project_root, self.root) / self.status_subdir


class IngestionSettings(_Base):
    batch_format: Literal["parquet", "auto"] = "parquet"
    column_layout: Literal["auto", "flat", "nested"] = "auto"
    require_manifest: bool = True
    verify_sha256: bool = True
    verify_file_size: bool = True
    allowed_schema_versions: list[str] = Field(default_factory=lambda: ["1.0.0"])
    fail_on_empty_batch: bool = False
    max_rows_per_batch: int = Field(default=1_000_000, ge=1)
    reject_future_timestamps_seconds: float = Field(default=3600.0, ge=0)
    reject_ancient_timestamps_year: int = 1990


class DedupSettings(_Base):
    by_event_id: bool = True
    content_hash: bool = True
    content_hash_time_bucket_seconds: float = Field(default=60.0, gt=0)


class EntityCorrelationSettings(_Base):
    same_attacker_required: bool = True
    attacker_subnet_prefix_v4: int = Field(default=32, ge=8, le=32)
    victim_subnet_prefix_v4: int = Field(default=24, ge=8, le=32)
    port_similarity_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    shared_ioc_bonus: float = Field(default=0.15, ge=0.0, le=1.0)


class BehaviorCorrelationSettings(_Base):
    rule_similarity_threshold: float = Field(default=0.34, ge=0.0, le=1.0)
    category_affinity: dict[str, float] = Field(
        default_factory=lambda: {
            "reconnaissance:initial_access": 0.9,
            "reconnaissance:credential_access": 0.7,
            "reconnaissance:discovery": 0.9,
            "initial_access:execution": 0.95,
            "initial_access:persistence": 0.6,
            "execution:lateral_movement": 0.9,
            "execution:command_and_control": 0.8,
            "credential_access:lateral_movement": 0.9,
            "discovery:lateral_movement": 0.85,
            "command_and_control:exfiltration": 0.9,
            "exfiltration:impact": 0.8,
        }
    )


class CorrelationWeights(_Base):
    time: float = 0.30
    attacker: float = 0.25
    victim: float = 0.20
    port: float = 0.10
    protocol: float = 0.05
    behavior: float = 0.10


class CorrelationSettings(_Base):
    correlation_window_seconds: float = Field(default=300.0, gt=0)
    max_gap_seconds: float = Field(default=600.0, gt=0)
    min_events_per_candidate: int = Field(default=1, ge=1)
    min_evidence_count: int = Field(default=2, ge=1)
    link_threshold: float = Field(default=0.55, ge=0.0, le=1.0)
    max_events_per_candidate: int = Field(default=5000, ge=1)
    entity: EntityCorrelationSettings = Field(default_factory=EntityCorrelationSettings)
    behavior: BehaviorCorrelationSettings = Field(default_factory=BehaviorCorrelationSettings)
    weights: CorrelationWeights = Field(default_factory=CorrelationWeights)


class ThreatIntelFiles(_Base):
    ip: str = "ip_reputation.parquet"
    domain: str = "domains.parquet"
    hash: str = "hashes.parquet"
    cve: str = "cve.parquet"


class RemoteThreatIntelSettings(_Base):
    enabled: bool = False
    provider: Literal["noop", "http"] = "noop"
    base_url: str | None = None
    api_key_env: str = "THREAT_INTEL_API_KEY"
    timeout_seconds: float = Field(default=5.0, gt=0)


class ThreatIntelSettings(_Base):
    enabled: bool = True
    provider: Literal["local", "noop"] = "local"
    path: str = "data/threat_intel"
    files: ThreatIntelFiles = Field(default_factory=ThreatIntelFiles)
    cache_size: int = Field(default=4096, ge=0)
    min_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    remote: RemoteThreatIntelSettings = Field(default_factory=RemoteThreatIntelSettings)


class AttackSettings(_Base):
    knowledge_base: str = "backend/module2_chain/attack/knowledge/attack_kb.yaml"
    min_technique_confidence: float = Field(default=0.3, ge=0.0, le=1.0)
    max_candidate_techniques: int = Field(default=8, ge=1)
    allow_multi_tactic: bool = True
    require_evidence_for_stage: bool = True
    max_stages_per_chain: int = Field(default=12, ge=1)


class AssetSettings(_Base):
    enabled: bool = True
    path: str = "data/assets/asset_inventory.parquet"
    default_weight: float = Field(default=1.0, gt=0)
    criticality_weights: dict[str, float] = Field(
        default_factory=lambda: {
            "critical": 3.0,
            "high": 2.0,
            "medium": 1.5,
            "low": 1.0,
            "unknown": 1.0,
        }
    )


class SeverityThresholds(_Base):
    critical: float = 85.0
    high: float = 70.0
    medium: float = 45.0
    low: float = 20.0


class RiskWeights(_Base):
    tactic_severity: float = 0.22
    evidence_strength: float = 0.14
    ioc: float = 0.14
    asset_criticality: float = 0.12
    rule_score: float = 0.12
    llm_confidence: float = 0.06
    m1_semantic: float = 0.06
    chain_length: float = 0.08
    multi_stage: float = 0.08


class ConfidenceWeights(_Base):
    evidence: float = 0.30
    rule: float = 0.20
    correlation: float = 0.20
    ioc: float = 0.10
    llm: float = 0.20


class RiskEvidenceSettings(_Base):
    min_events_for_high_confidence: int = Field(default=3, ge=1)
    max_events_for_full_score: int = Field(default=6, ge=1)
    penalty_per_validation_issue: float = Field(default=0.05, ge=0.0, le=1.0)
    max_validation_penalty: float = Field(default=0.4, ge=0.0, le=1.0)
    llm_hallucination_penalty: float = Field(default=0.25, ge=0.0, le=1.0)


class RiskSettings(_Base):
    severity_thresholds: SeverityThresholds = Field(default_factory=SeverityThresholds)
    weights: RiskWeights = Field(default_factory=RiskWeights)
    confidence_weights: ConfidenceWeights = Field(default_factory=ConfidenceWeights)
    confidence_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    evidence: RiskEvidenceSettings = Field(default_factory=RiskEvidenceSettings)
    tactic_severity: dict[str, float] = Field(
        default_factory=lambda: {
            "TA0043": 0.35,
            "TA0042": 0.35,
            "TA0001": 0.85,
            "TA0002": 0.8,
            "TA0003": 0.75,
            "TA0004": 0.8,
            "TA0005": 0.6,
            "TA0006": 0.8,
            "TA0007": 0.4,
            "TA0008": 0.9,
            "TA0009": 0.7,
            "TA0011": 0.75,
            "TA0010": 0.9,
            "TA0040": 1.0,
        }
    )


class DeepSeekSettings(_Base):
    base_url: str = "https://api.deepseek.com/v1"
    model: str = "deepseek-chat"
    api_key: SecretStr | None = None
    api_key_env: str = "DEEPSEEK_API_KEY"
    transport: Literal["auto", "sdk", "httpx"] = "httpx"
    response_format: Literal["json_object", "none"] = "json_object"
    extra_headers: dict[str, str] = Field(default_factory=dict)
    extra_body: dict[str, Any] = Field(default_factory=dict)

    def resolved_api_key(self) -> str | None:
        if self.api_key is not None and self.api_key.get_secret_value():
            return self.api_key.get_secret_value()
        return os.environ.get(self.api_key_env) or None


class FineTunedSettings(_Base):
    base_url: str = ""
    model: str = ""
    api_key: SecretStr | None = None
    api_key_env: str = "FINETUNED_API_KEY"
    timeout_seconds: float | None = Field(default=None, gt=0)
    transport: Literal["auto", "sdk", "httpx"] = "httpx"
    response_format: Literal["json_object", "none"] = "json_object"
    extra_headers: dict[str, str] = Field(default_factory=dict)
    extra_body: dict[str, Any] = Field(default_factory=dict)
    system_prompt: str | None = None
    strict: bool = False

    def resolved_api_key(self) -> str | None:
        if self.api_key is not None and self.api_key.get_secret_value():
            return self.api_key.get_secret_value()
        return os.environ.get(self.api_key_env) or None


class MockSettings(_Base):
    fixture: str | None = "tests/fixtures/llm/mock_attack_analysis.json"
    latency_ms: float = Field(default=0.0, ge=0)
    fail_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    failure_mode: Literal["none", "timeout", "provider_error", "invalid_json", "schema_error"] = (
        "none"
    )
    seed: int = 1337


class LLMProvidersSettings(_Base):
    # All three cloud services use the OpenAI-compatible transport.  Keeping
    # separate settings preserves vendor/model provenance in task artifacts.
    opencode_go: DeepSeekSettings = Field(default_factory=lambda: DeepSeekSettings(
        base_url="https://opencode.ai/zen/go/v1", model="glm-5.3-flash",
        api_key_env="OPENCODE_API_KEY", response_format="none"))
    commandcode: DeepSeekSettings = Field(default_factory=lambda: DeepSeekSettings(
        base_url="https://api.commandcode.ai/provider/v1", model="z-ai/glm-5.3-flash",
        api_key_env="COMMANDCODE_API_KEY", response_format="none"))
    deepseek: DeepSeekSettings = Field(default_factory=DeepSeekSettings)
    finetuned: FineTunedSettings = Field(default_factory=FineTunedSettings)
    mock: MockSettings = Field(default_factory=MockSettings)


class LLMSettings(_Base):
    provider: Literal["cloud_chain", "opencode_go", "commandcode", "deepseek", "finetuned", "mock", "disabled"] = "cloud_chain"
    prompt_version: str = "attack_analysis.v1"
    prompt_dir: str = "backend/module2_chain/llm/prompts"
    max_concurrency: int = Field(default=5, ge=1)
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_retries: int = Field(default=2, ge=0, le=10)
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_input_events: int = Field(default=40, ge=1)
    max_evidence_chars: int = Field(default=12_000, ge=500)
    max_payload_snippet_chars: int = Field(default=0, ge=0)
    max_output_tokens: int = Field(default=2000, ge=64)
    record_tokens: bool = True
    fail_open: bool = True
    min_events_for_llm: int = Field(default=1, ge=1)
    #: 每任务送 LLM 的候选数上限（按风险分 Top-N 选取，0 = 不限制；其余候选走规则降级）。
    max_candidates: int = Field(default=0, ge=0)
    providers: LLMProvidersSettings = Field(default_factory=LLMProvidersSettings)


class PersistenceSettings(_Base):
    sqlite_path: str = "06_status/m2/module2_state.db"
    enable_registry: bool = True
    busy_timeout_ms: int = Field(default=5000, ge=0)


class LoggingSettings(_Base):
    level: str = "INFO"
    format: Literal["json", "text"] = "json"
    include_payload: bool = False
    redact_keys: list[str] = Field(
        default_factory=lambda: [
            "api_key",
            "apikey",
            "authorization",
            "token",
            "password",
            "secret",
        ]
    )
    file: str | None = None


class PerformanceSettings(_Base):
    enable_metrics: bool = True
    track_stage_timings: bool = True
    warn_events_per_second_below: float = 500.0
    metrics_file: str = "metrics.json"


class AppConfig(BaseModel):
    """Root configuration object."""

    model_config = ConfigDict(extra="forbid")

    config_version: str = "1.0.0"
    project_root: str = "."
    app: AppSettings = Field(default_factory=AppSettings)
    workspace: WorkspaceSettings = Field(default_factory=WorkspaceSettings)
    ingestion: IngestionSettings = Field(default_factory=IngestionSettings)
    dedup: DedupSettings = Field(default_factory=DedupSettings)
    correlation: CorrelationSettings = Field(default_factory=CorrelationSettings)
    threat_intel: ThreatIntelSettings = Field(default_factory=ThreatIntelSettings)
    attack: AttackSettings = Field(default_factory=AttackSettings)
    assets: AssetSettings = Field(default_factory=AssetSettings)
    risk: RiskSettings = Field(default_factory=RiskSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    persistence: PersistenceSettings = Field(default_factory=PersistenceSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    performance: PerformanceSettings = Field(default_factory=PerformanceSettings)

    # ------------------------------------------------------------------ #
    # Derived paths
    # ------------------------------------------------------------------ #
    @property
    def root_path(self) -> Path:
        return Path(self.project_root).expanduser().resolve()

    def path(self, value: str) -> Path:
        """Resolve a configuration path against the project root."""

        candidate = Path(value).expanduser()
        return candidate if candidate.is_absolute() else (self.root_path / candidate)

    @property
    def inbox_dir(self) -> Path:
        return self.workspace.inbox_path(self.root_path)

    @property
    def output_dir(self) -> Path:
        return self.workspace.output_path(self.root_path)

    @property
    def status_dir(self) -> Path:
        return self.workspace.status_path(self.root_path)

    @property
    def threat_intel_dir(self) -> Path:
        return self.path(self.threat_intel.path)

    @property
    def attack_kb_path(self) -> Path:
        return self.path(self.attack.knowledge_base)

    @property
    def prompt_dir(self) -> Path:
        return self.path(self.llm.prompt_dir)

    @property
    def sqlite_path(self) -> Path:
        return self.path(self.persistence.sqlite_path)

    @property
    def asset_path(self) -> Path:
        return self.path(self.assets.path)


def _resolve(project_root: Path, value: str) -> Path:
    candidate = Path(value).expanduser()
    return candidate if candidate.is_absolute() else (project_root / candidate)


# ---------------------------------------------------------------------- #
# Environment overlays
# ---------------------------------------------------------------------- #
#: ``ENV_VAR -> dotted config path``.  Adding a tunable to the environment
#: never requires touching business code.
ENV_OVERRIDES: dict[str, str] = {
    "M2_PROJECT_ROOT": "project_root",
    "M2_ENVIRONMENT": "app.environment",
    "M2_FAIL_FAST": "app.fail_fast",
    "M2_MAX_EVENTS_PER_TASK": "app.max_events_per_task",
    "WORKSPACE_PATH": "workspace.root",
    "WORKSPACE_INBOX_SUBDIR": "workspace.inbox_subdir",
    "WORKSPACE_OUTPUT_SUBDIR": "workspace.output_subdir",
    "WORKSPACE_STATUS_SUBDIR": "workspace.status_subdir",
    "CORRELATION_WINDOW_SECONDS": "correlation.correlation_window_seconds",
    "CORRELATION_MAX_GAP_SECONDS": "correlation.max_gap_seconds",
    "CORRELATION_LINK_THRESHOLD": "correlation.link_threshold",
    "MIN_EVIDENCE_COUNT": "correlation.min_evidence_count",
    "THREAT_INTEL_ENABLED": "threat_intel.enabled",
    "THREAT_INTEL_PROVIDER": "threat_intel.provider",
    "THREAT_INTEL_PATH": "threat_intel.path",
    "LLM_PROVIDER": "llm.provider",
    "LLM_PROMPT_VERSION": "llm.prompt_version",
    "LLM_TIMEOUT_SECONDS": "llm.timeout_seconds",
    "LLM_MAX_RETRIES": "llm.max_retries",
    "LLM_TEMPERATURE": "llm.temperature",
    "LLM_MAX_CONCURRENCY": "llm.max_concurrency",
    "LLM_FAIL_OPEN": "llm.fail_open",
    "DEEPSEEK_API_KEY": "llm.providers.deepseek.api_key",
    "OPENCODE_API_KEY": "llm.providers.opencode_go.api_key",
    "COMMANDCODE_API_KEY": "llm.providers.commandcode.api_key",
    "DEEPSEEK_BASE_URL": "llm.providers.deepseek.base_url",
    "DEEPSEEK_MODEL": "llm.providers.deepseek.model",
    "DEEPSEEK_TRANSPORT": "llm.providers.deepseek.transport",
    "OPENCODE_GO_BASE_URL": "llm.providers.opencode_go.base_url",
    "OPENCODE_GO_MODEL": "llm.providers.opencode_go.model",
    "COMMANDCODE_BASE_URL": "llm.providers.commandcode.base_url",
    "COMMANDCODE_MODEL": "llm.providers.commandcode.model",
    "FINETUNED_API_BASE_URL": "llm.providers.finetuned.base_url",
    "FINETUNED_API_KEY": "llm.providers.finetuned.api_key",
    "FINETUNED_MODEL": "llm.providers.finetuned.model",
    "FINETUNED_TIMEOUT_SECONDS": "llm.providers.finetuned.timeout_seconds",
    "MOCK_LLM_FIXTURE": "llm.providers.mock.fixture",
    "MOCK_LLM_FAILURE_MODE": "llm.providers.mock.failure_mode",
    "MOCK_LLM_FAIL_RATE": "llm.providers.mock.fail_rate",
    "LOG_LEVEL": "logging.level",
    "LOG_FORMAT": "logging.format",
    "SQLITE_PATH": "persistence.sqlite_path",
}

_BOOL_TRUE = {"1", "true", "yes", "on", "y"}
_BOOL_FALSE = {"0", "false", "no", "off", "n"}


def read_dotenv(path: Path) -> dict[str, str]:
    """Minimal ``.env`` reader (``KEY=VALUE``, ``#`` comments, optional quotes)."""

    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def _coerce_scalar(raw: str) -> Any:
    lowered = raw.strip().lower()
    if lowered in _BOOL_TRUE:
        return True
    if lowered in _BOOL_FALSE:
        return False
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


def _set_by_path(payload: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cursor: dict[str, Any] = payload
    for part in parts[:-1]:
        nxt = cursor.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[part] = nxt
        cursor = nxt
    cursor[parts[-1]] = value


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigError(f"config root must be a mapping, got {type(loaded).__name__}")
    return loaded


def load_config(
    config_path: str | Path | None = None,
    *,
    project_root: str | Path | None = None,
    env: dict[str, str] | None = None,
    dotenv_path: str | Path | None = None,
    apply_env: bool = True,
) -> AppConfig:
    """Build the effective configuration.

    Parameters
    ----------
    config_path:
        ``config.yaml`` location.  Defaults to ``$M2_CONFIG_FILE`` or
        ``<cwd>/config.yaml``.
    project_root:
        Overrides ``project_root`` (useful in tests).
    env:
        Environment mapping override (defaults to ``os.environ``).
    """

    environment = dict(os.environ if env is None else env)
    resolved_config_path = Path(
        config_path
        or environment.get(DEFAULT_CONFIG_ENV_VAR)
        or (Path.cwd() / "config.yaml")
    ).expanduser()

    payload = _load_yaml(resolved_config_path)

    resolved_dotenv = Path(
        dotenv_path
        or environment.get(DEFAULT_DOTENV_ENV_VAR)
        or (resolved_config_path.parent / ".env")
    ).expanduser()
    dotenv_values = read_dotenv(resolved_dotenv)

    if "project_root" not in payload:
        payload["project_root"] = str(resolved_config_path.parent.resolve())

    if apply_env:
        merged_env = {**dotenv_values, **environment}
        for env_name, dotted in ENV_OVERRIDES.items():
            if env_name in merged_env and merged_env[env_name] != "":
                _set_by_path(payload, dotted, _coerce_scalar(merged_env[env_name]))

    if project_root is not None:
        payload["project_root"] = str(Path(project_root).expanduser().resolve())

    try:
        config = AppConfig.model_validate(payload)
    except ValidationError as exc:  # pragma: no cover - defensive
        raise ConfigError(f"invalid configuration: {exc}") from exc
    return config


@lru_cache(maxsize=8)
def _cached_config(config_path: str, project_root: str | None) -> AppConfig:
    return load_config(config_path or None, project_root=project_root)


def get_config(
    config_path: str | Path | None = None,
    *,
    project_root: str | Path | None = None,
) -> AppConfig:
    """Cached accessor used by CLI entry points."""

    resolved = str(
        Path(
            config_path
            or os.environ.get(DEFAULT_CONFIG_ENV_VAR)
            or (Path.cwd() / "config.yaml")
        ).expanduser()
    )
    return _cached_config(resolved, str(project_root) if project_root else None)


def reset_config_cache() -> None:
    """Clear the :func:`get_config` cache (tests, long running watchers)."""

    _cached_config.cache_clear()


def validate_config_file(path: str | Path) -> AppConfig:
    """Validate a configuration file, raising :class:`ConfigError` on error."""

    adapter = TypeAdapter(AppConfig)
    payload = _load_yaml(Path(path).expanduser())
    try:
        return adapter.validate_python(payload)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
