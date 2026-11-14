"""Contract tests: shared schemas, workspace protocol, module independence.

These tests protect the three principles that must never be broken:

1. module independence - no module-to-module network call of any kind;
2. stable data contracts - v1 is additive only;
3. replaceable LLM - business code only knows the ``LLMProvider`` interface.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from backend.common.schemas.workspace import (
    BUNDLE_DIR_ALERTS,
    BUNDLE_DIR_ATTACKERS,
    BUNDLE_DIR_CHAINS,
    BUNDLE_DIR_ENTITIES,
    BUNDLE_DIR_REPORTS,
    DONE_MARKER,
    MANIFEST_FILE,
    METRICS_FILE,
    PROCESSING_MARKER,
    READY_MARKER,
)
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.devtools.synthetic import build_mixed_batch, write_batch

PROJECT_ROOT = Path(__file__).resolve().parents[4]
MODULE_ROOT = PROJECT_ROOT / "backend" / "module2_chain"
COMMON_ROOT = PROJECT_ROOT / "backend" / "common"

#: Libraries that would imply a module-to-module network call.
FORBIDDEN_NETWORK_IMPORTS = (
    "socket",
    "socketserver",
    "http.server",
    "urllib.request",
    "requests",
    "aiohttp",
    "fastapi",
    "flask",
    "starlette",
    "uvicorn",
    "grpc",
    "redis",
    "kafka",
    "pika",
    "zmq",
    "websockets",
    "xmlrpc",
    "pyspark",
    "celery",
)

#: ``httpx`` is only allowed for talking to the *LLM provider API*, never to
#: another module of this system.
HTTPX_ALLOWED_FILES = {"client.py"}

#: Vendor SDKs may only appear inside the pluggable LLM layer.
VENDOR_ALLOWED_PREFIXES = ("llm/",)
VENDOR_PACKAGES = ("openai", "anthropic", "deepseek", "dashscope", "zhipuai")


def _python_files(root: Path) -> list[Path]:
    return [
        path
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts
    ]


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


def _production_files(root: Path) -> list[Path]:
    return [path for path in _python_files(root) if "tests" not in path.parts]


def test_module2_has_no_network_or_queue_transport() -> None:
    offenders: list[str] = []
    for path in _production_files(MODULE_ROOT):
        imports = _imports(path)
        for module in imports:
            root = module.split(".")[0]
            if module in FORBIDDEN_NETWORK_IMPORTS or root in {
                "socket",
                "requests",
                "aiohttp",
                "fastapi",
                "flask",
                "grpc",
                "redis",
                "kafka",
                "pika",
                "zmq",
                "websockets",
            }:
                offenders.append(f"{path.relative_to(PROJECT_ROOT)}: {module}")
            if root == "httpx" and path.name not in HTTPX_ALLOWED_FILES:
                offenders.append(f"{path.relative_to(PROJECT_ROOT)}: httpx used outside llm/client.py")
    assert not offenders, "module-to-module networking must not exist: " + "; ".join(offenders)


def test_module2_exposes_no_http_api() -> None:
    """No API routes, no servers, no RPC handlers anywhere in Module 2."""

    forbidden_markers = (
        "@app.get",
        "@app.post",
        "@router.",
        "FastAPI(",
        "APIRouter(",
        "Flask(__name__)",
        "uvicorn.run",
        "serve_forever(",
        "add_insecure_port",
    )
    offenders: list[str] = []
    for path in _python_files(MODULE_ROOT):
        if "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        for marker in forbidden_markers:
            if marker in source:
                offenders.append(f"{path.relative_to(PROJECT_ROOT)}: {marker}")
    assert not offenders, "Module 2 must not provide an API: " + "; ".join(offenders)


def test_vendor_sdks_are_confined_to_the_llm_layer() -> None:
    offenders: list[str] = []
    for path in _python_files(MODULE_ROOT):
        relative = path.relative_to(MODULE_ROOT).as_posix()
        if relative.startswith(VENDOR_ALLOWED_PREFIXES):
            continue
        for module in _imports(path):
            root = module.split(".")[0]
            if root in VENDOR_PACKAGES:
                offenders.append(f"{relative}: {module}")
    assert not offenders, "vendor SDKs leaked into business code: " + "; ".join(offenders)


def test_business_layer_depends_only_on_the_provider_protocol() -> None:
    pipeline_source = (MODULE_ROOT / "pipeline.py").read_text(encoding="utf-8")
    assert "from backend.module2_chain.llm.base import LLMProvider" in pipeline_source
    assert "from backend.module2_chain.llm.factory import create_llm_provider" in pipeline_source
    for banned in ("DeepSeekProvider", "FineTunedModelProvider", "MockLLMProvider", "openai"):
        assert banned not in pipeline_source, f"{banned} must not appear in the business layer"


def test_common_schemas_never_import_a_concrete_module() -> None:
    offenders: list[str] = []
    for path in _python_files(COMMON_ROOT):
        for module in _imports(path):
            if "module1" in module or "module2" in module or "module3" in module:
                offenders.append(f"{path.name}: {module}")
    assert not offenders


def test_workspace_marker_constants_are_the_documented_protocol() -> None:
    assert READY_MARKER == "READY"
    assert PROCESSING_MARKER == "PROCESSING"
    assert DONE_MARKER == "DONE"
    assert MANIFEST_FILE == "manifest.json"
    assert METRICS_FILE == "metrics.json"
    assert {BUNDLE_DIR_CHAINS, BUNDLE_DIR_ALERTS, BUNDLE_DIR_ATTACKERS, BUNDLE_DIR_ENTITIES, BUNDLE_DIR_REPORTS} == {
        "chains",
        "alerts",
        "attackers",
        "entities",
        "reports",
    }


def test_fixture_batch_folder_follows_the_delivery_protocol(fixtures_dir: Path) -> None:
    task_dir = fixtures_dir / "events" / "task_fixture_events"
    assert (task_dir / READY_MARKER).is_file()
    assert (task_dir / MANIFEST_FILE).is_file()
    assert not list(task_dir.glob("*.tmp"))
    manifest = json.loads((task_dir / MANIFEST_FILE).read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "1.0.0"
    assert manifest["task_id"] == "task_fixture_events"
    assert manifest["producer"]
    for ref in manifest["files"]:
        assert len(ref["sha256"]) == 64
        assert ref["size_bytes"] > 0
        assert (task_dir / ref["path"]).is_file()


async def test_bundle_is_only_consumable_after_done(config: AppConfig, pipeline) -> None:
    write_batch(
        config.inbox_dir, build_mixed_batch(task_id="task_contract")[:6], task_id="task_contract"
    )
    outcomes = await pipeline.run_once(max_tasks=1)
    bundle = outcomes[0].bundle_path
    assert bundle is not None
    assert (bundle / DONE_MARKER).is_file()
    assert not list(bundle.rglob("*.tmp"))
    assert not (config.output_dir / "task_contract.tmp").exists()

    manifest = json.loads((bundle / MANIFEST_FILE).read_text(encoding="utf-8"))
    assert manifest["schema_versions"]["attack_chain"] == "1.0.0"
    assert manifest["schema_versions"]["alert"] == "1.0.0"
    assert manifest["schema_versions"]["attacker_profile"] == "1.0.0"
    assert manifest["schema_versions"]["threat_entity"] == "1.0.0"
    assert manifest["schema_versions"]["risk_event_report"] == "1.0.0"
    listed = {ref["path"] for ref in manifest["files"]}
    for required in (
        "chains/chains.json",
        "chains.json",
        "alerts/alerts.json",
        "attackers/attackers.json",
        "entities/entities.json",
        "reports/report.json",
        "metrics.json",
    ):
        assert required in listed, required


async def test_module3_can_read_the_bundle_without_module2_running(
    config: AppConfig, pipeline
) -> None:
    """All Module 3 needs is the published bundle and the public schemas."""

    from backend.common.schemas.alert import Alert
    from backend.common.schemas.attack import AttackChain
    from backend.common.schemas.entity import ThreatEntity
    from backend.common.schemas.profile import AttackerProfile
    from backend.common.schemas.report import RiskEventReport

    write_batch(
        config.inbox_dir, build_mixed_batch(task_id="task_m3")[:8], task_id="task_m3"
    )
    outcomes = await pipeline.run_once(max_tasks=1)
    bundle = outcomes[0].bundle_path
    assert bundle is not None

    chains = [AttackChain.model_validate(item) for item in _load(bundle / "chains.json")]
    alerts = [Alert.model_validate(item) for item in _load(bundle / "alerts.json")]
    attackers = [AttackerProfile.model_validate(item) for item in _load(bundle / "attackers.json")]
    entities = [ThreatEntity.model_validate(item) for item in _load(bundle / "entities.json")]
    report = RiskEventReport.model_validate(_load(bundle / "reports" / "report.json"))

    assert chains and alerts
    assert report.statistics.total_attack_events == len(chains)
    assert {alert.chain_id for alert in alerts} == {chain.chain_id for chain in chains}
    assert all(entity.evidence_event_ids for entity in entities if entity.value)
    if attackers:
        assert all(profile.attribution == "Not Determined" for profile in attackers)
    for chain in chains:
        stage_indexes = [stage.stage_index for stage in chain.stages]
        assert stage_indexes == sorted(stage_indexes) == list(
            range(1, len(stage_indexes) + 1)
        )


def test_suspicious_event_contract_fields_are_stable() -> None:
    from backend.common.schemas.suspicious_event import SuspiciousEvent

    schema = SuspiciousEvent.model_json_schema()
    event_props = schema["$defs"]["EventCore"]["properties"]
    detection_props = schema["$defs"]["Detection"]["properties"]
    assert {
        "event_id",
        "task_id",
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "payload_digest",
        "raw_ref",
        "source_file",
    } <= set(event_props)
    assert {"matched_rules", "ioc_hits", "score", "reason", "detector"} <= set(
        detection_props
    )
    assert {"event", "detection", "session_id", "emitted_at"} <= set(schema["properties"])


@pytest.mark.parametrize(
    "attribute",
    [
        "correlation_window_seconds",
        "min_evidence_count",
        "link_threshold",
    ],
)
def test_correlation_thresholds_are_configurable(config: AppConfig, attribute: str) -> None:
    assert hasattr(config.correlation, attribute)


def test_llm_settings_are_configurable(config: AppConfig) -> None:
    assert hasattr(config.llm, "provider")
    assert hasattr(config.llm, "max_concurrency")
    assert hasattr(config.llm, "timeout_seconds")
    assert hasattr(config.llm, "max_retries")
    assert hasattr(config.llm.providers, "deepseek")
    assert hasattr(config.llm.providers, "finetuned")
    assert hasattr(config.llm.providers, "mock")
    assert hasattr(config, "threat_intel_path" if False else "threat_intel")
    assert hasattr(config.workspace, "root")


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))
