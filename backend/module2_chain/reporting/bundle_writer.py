"""Atomic Module 2 output bundle writer (M2-F20, spec §30).

Delivery protocol (identical to Module 1 -> Module 2):

1. write everything into ``05_m2_output/task_xxx.tmp/``,
2. hash + fsync every artefact, write ``manifest.json``,
3. ``os.replace`` the temporary directory onto ``05_m2_output/task_xxx/``,
4. create ``DONE`` **last**.

Module 3 may only consume a folder once ``DONE`` exists.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.common.schemas.alert import Alert
from backend.common.schemas.attack import AttackChain
from backend.common.schemas.bundle import BundleFileRef, BundleManifest
from backend.common.schemas.entity import ThreatEntity
from backend.common.schemas.profile import AttackerProfile
from backend.common.schemas.report import RiskEventReport
from backend.common.schemas.version import (
    ALERT_SCHEMA_VERSION,
    ATTACK_CHAIN_SCHEMA_VERSION,
    ATTACKER_PROFILE_SCHEMA_VERSION,
    RISK_EVENT_REPORT_SCHEMA_VERSION,
    THREAT_ENTITY_SCHEMA_VERSION,
)
from backend.common.schemas.workspace import (
    BUNDLE_DIR_ALERTS,
    BUNDLE_DIR_ATTACKERS,
    BUNDLE_DIR_CHAINS,
    BUNDLE_DIR_ENTITIES,
    BUNDLE_DIR_EVIDENCE,
    BUNDLE_DIR_REPORTS,
    DONE_MARKER,
    METRICS_FILE,
)
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.reporting.atomic_io import (
    atomic_write_json,
    fsync_directory,
    sha256_file,
)

logger = get_logger("reporting.bundle_writer")

MANIFEST_NAME = "manifest.json"
TEMP_DIR_SUFFIX = ".tmp"


@dataclass(slots=True)
class BundlePayload:
    """Everything a Module 2 bundle contains."""

    task_id: str
    chains: list[AttackChain] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    attackers: list[AttackerProfile] = field(default_factory=list)
    entities: list[ThreatEntity] = field(default_factory=list)
    report: RiskEventReport | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    input_batches: list[str] = field(default_factory=list)
    input_checksums: list[str] = field(default_factory=list)
    run: dict[str, Any] = field(default_factory=dict)
    per_item_files: bool = True
    parquet_mirrors: bool = True


@dataclass(slots=True)
class BundleResult:
    """Where the bundle landed and what it contains."""

    task_id: str
    bundle_dir: Path
    manifest_path: Path
    done_marker: Path
    files: list[BundleFileRef]
    counts: dict[str, int]


class BundleWriter:
    """Writes ``05_m2_output/task_xxx`` atomically."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.output_dir = config.output_dir

    # ------------------------------------------------------------------ #
    def write(self, payload: BundlePayload) -> BundleResult:
        task_id = payload.task_id
        self.output_dir.mkdir(parents=True, exist_ok=True)
        final_dir = self.output_dir / task_id
        temp_dir = self.output_dir / f"{task_id}{TEMP_DIR_SUFFIX}"
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        temp_dir.mkdir(parents=True, exist_ok=True)

        try:
            files = self._write_bundle(temp_dir, payload)
            manifest = self._manifest(payload, files)
            manifest_path = atomic_write_json(
                temp_dir / MANIFEST_NAME,
                manifest.model_dump(mode="json"),
                fsync=self.config.workspace.atomic_write.fsync,
            )
            files.append(self._ref(manifest_path, temp_dir, record_count=None))
            fsync_directory(temp_dir)
            self._replace_directory(temp_dir, final_dir)
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

        done_marker = self._publish_done(final_dir, task_id)
        logger.info(
            "module2 bundle published",
            extra={
                "task_id": task_id,
                "stage": "bundle_write",
                "bundle": str(final_dir),
                "files": len(files),
            },
        )
        return BundleResult(
            task_id=task_id,
            bundle_dir=final_dir,
            manifest_path=final_dir / MANIFEST_NAME,
            done_marker=done_marker,
            files=files,
            counts=self._counts(payload),
        )

    # ------------------------------------------------------------------ #
    def _write_bundle(self, base: Path, payload: BundlePayload) -> list[BundleFileRef]:
        fsync = self.config.workspace.atomic_write.fsync
        refs: list[BundleFileRef] = []

        chains_dump = [chain.model_dump(mode="json") for chain in payload.chains]
        alerts_dump = [alert.model_dump(mode="json") for alert in payload.alerts]
        attackers_dump = [profile.model_dump(mode="json") for profile in payload.attackers]
        entities_dump = [entity.model_dump(mode="json") for entity in payload.entities]

        refs.extend(
            self._write_collection(
                base,
                BUNDLE_DIR_CHAINS,
                "chains",
                chains_dump,
                ATTACK_CHAIN_SCHEMA_VERSION,
                per_item=payload.per_item_files,
                item_key="chain_id",
                fsync=fsync,
            )
        )
        refs.extend(
            self._write_collection(
                base,
                BUNDLE_DIR_ALERTS,
                "alerts",
                alerts_dump,
                ALERT_SCHEMA_VERSION,
                per_item=payload.per_item_files,
                item_key="alert_id",
                fsync=fsync,
            )
        )
        refs.extend(
            self._write_collection(
                base,
                BUNDLE_DIR_ATTACKERS,
                "attackers",
                attackers_dump,
                ATTACKER_PROFILE_SCHEMA_VERSION,
                per_item=payload.per_item_files,
                item_key="attacker_id",
                fsync=fsync,
            )
        )
        refs.extend(
            self._write_collection(
                base,
                BUNDLE_DIR_ENTITIES,
                "entities",
                entities_dump,
                THREAT_ENTITY_SCHEMA_VERSION,
                per_item=payload.per_item_files,
                item_key="entity_id",
                fsync=fsync,
            )
        )

        if payload.report is not None:
            report_dir = base / BUNDLE_DIR_REPORTS
            report_path = atomic_write_json(
                report_dir / "report.json",
                payload.report.model_dump(mode="json"),
                fsync=fsync,
            )
            refs.append(
                self._ref(
                    report_path,
                    base,
                    record_count=1,
                    schema_version=RISK_EVENT_REPORT_SCHEMA_VERSION,
                )
            )

        if payload.evidence:
            evidence_path = atomic_write_json(
                base / BUNDLE_DIR_EVIDENCE / "evidence_summary.json",
                payload.evidence,
                fsync=fsync,
            )
            refs.append(self._ref(evidence_path, base, record_count=len(payload.evidence)))

        if payload.metrics:
            metrics_path = atomic_write_json(
                base / METRICS_FILE, payload.metrics, fsync=fsync
            )
            refs.append(self._ref(metrics_path, base, record_count=None))

        if payload.parquet_mirrors:
            mirror_refs = self._write_parquet_mirrors(
                base, chains_dump, alerts_dump, entities_dump
            )
            refs.extend(mirror_refs)
        return refs

    def _write_collection(
        self,
        base: Path,
        directory: str,
        name: str,
        items: list[dict[str, Any]],
        schema_version: str,
        *,
        per_item: bool,
        item_key: str,
        fsync: bool,
    ) -> list[BundleFileRef]:
        target_dir = base / directory
        target_dir.mkdir(parents=True, exist_ok=True)
        array_path = atomic_write_json(target_dir / f"{name}.json", items, fsync=fsync)
        # Convenience copy at the bundle root: M3 may read either location.
        atomic_write_json(base / f"{name}.json", items, fsync=fsync)
        if per_item:
            for item in items:
                identifier = str(item.get(item_key) or "unknown")
                atomic_write_json(target_dir / f"{identifier}.json", item, fsync=fsync)
        refs = [
            self._ref(
                array_path, base, record_count=len(items), schema_version=schema_version
            ),
            # Root copy: Module 3 may read either location, so both are hashed.
            self._ref(
                base / f"{name}.json",
                base,
                record_count=len(items),
                schema_version=schema_version,
            ),
        ]
        return refs

    def _write_parquet_mirrors(
        self,
        base: Path,
        chains: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
        entities: list[dict[str, Any]],
    ) -> list[BundleFileRef]:
        """Columnar mirrors for large bundles (Module 3 can scan them in bulk)."""

        try:
            import polars as pl
        except ImportError:  # pragma: no cover - polars is a hard dependency
            return []

        refs: list[BundleFileRef] = []
        chain_rows = [_flatten_chain(chain) for chain in chains]
        alert_rows = [_flatten_alert(alert) for alert in alerts]
        entity_rows = [_flatten_entity(entity) for entity in entities]
        for rows, directory, name, schema_version in (
            (chain_rows, BUNDLE_DIR_CHAINS, "chains", ATTACK_CHAIN_SCHEMA_VERSION),
            (alert_rows, BUNDLE_DIR_ALERTS, "alerts", ALERT_SCHEMA_VERSION),
            (entity_rows, BUNDLE_DIR_ENTITIES, "entities", THREAT_ENTITY_SCHEMA_VERSION),
        ):
            if not rows:
                continue
            path = base / directory / f"{name}.parquet"
            path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = path.with_name(path.name + ".tmp")
            try:
                pl.DataFrame(rows, infer_schema_length=None).write_parquet(temp_path)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "failed to write parquet mirror",
                    extra={"stage": "bundle_write", "path": str(path), "error": str(exc)},
                )
                temp_path.unlink(missing_ok=True)
                continue
            os.replace(temp_path, path)
            refs.append(
                self._ref(path, base, record_count=len(rows), schema_version=schema_version)
            )
        return refs

    def _manifest(self, payload: BundlePayload, files: list[BundleFileRef]) -> BundleManifest:
        manifest = BundleManifest(
            task_id=payload.task_id,
            files=files,
            counts=self._counts(payload),
            schema_versions={
                "attack_chain": ATTACK_CHAIN_SCHEMA_VERSION,
                "alert": ALERT_SCHEMA_VERSION,
                "attacker_profile": ATTACKER_PROFILE_SCHEMA_VERSION,
                "threat_entity": THREAT_ENTITY_SCHEMA_VERSION,
                "risk_event_report": RISK_EVENT_REPORT_SCHEMA_VERSION,
            },
            input_batches=list(payload.input_batches),
            input_checksums=list(payload.input_checksums),
            run=dict(payload.run),
        )
        return manifest

    @staticmethod
    def _counts(payload: BundlePayload) -> dict[str, int]:
        return {
            "chains": len(payload.chains),
            "alerts": len(payload.alerts),
            "attackers": len(payload.attackers),
            "entities": len(payload.entities),
            "reports": 1 if payload.report is not None else 0,
        }

    def _replace_directory(self, temp_dir: Path, final_dir: Path) -> None:
        if final_dir.exists():
            backup = final_dir.with_name(final_dir.name + ".previous")
            if backup.exists():
                shutil.rmtree(backup)
            os.replace(final_dir, backup)
            os.replace(temp_dir, final_dir)
            shutil.rmtree(backup, ignore_errors=True)
        else:
            os.replace(temp_dir, final_dir)

    def _publish_done(self, final_dir: Path, task_id: str) -> Path:
        marker = final_dir / DONE_MARKER
        atomic_write_json(
            marker,
            {
                "task_id": task_id,
                "producer": "module2_chain",
                "completed_at": datetime.now(UTC).isoformat(),
                "manifest": MANIFEST_NAME,
            },
            fsync=self.config.workspace.atomic_write.fsync,
        )
        return marker

    @staticmethod
    def _ref(
        path: Path,
        base: Path,
        *,
        record_count: int | None = None,
        schema_version: str | None = None,
    ) -> BundleFileRef:
        return BundleFileRef(
            # manifest 中的路径契约用 POSIX 分隔符，Windows 下 str(Path) 会产出反斜杠
            path=path.relative_to(base).as_posix(),
            sha256=sha256_file(path),
            size_bytes=path.stat().st_size,
            content_type=_content_type(path),
            record_count=record_count,
            schema_version=schema_version,
        )


def _content_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix == ".parquet":
        return "application/vnd.apache.parquet"
    return "application/octet-stream"


def _flatten_chain(chain: dict[str, Any]) -> dict[str, Any]:
    stages = chain.get("stages") or []
    return {
        "chain_id": chain.get("chain_id"),
        "task_id": chain.get("task_id"),
        "severity": chain.get("severity"),
        "confidence": chain.get("confidence"),
        "risk_score": (chain.get("risk_score") or {}).get("score"),
        "stage_count": len(stages),
        "tactics": [stage.get("tactic") for stage in stages if stage.get("tactic")],
        "techniques": [stage.get("technique") for stage in stages if stage.get("technique")],
        "attacker_ips": chain.get("attacker_ips") or [],
        "victim_ips": chain.get("victim_ips") or [],
        "victim_ports": chain.get("victim_ports") or [],
        "event_count": len(chain.get("event_ids") or []),
        "evidence_event_ids": sorted(
            {
                event_id
                for stage in stages
                for event_id in (stage.get("evidence_event_ids") or [])
            }
        ),
        "fingerprint": chain.get("fingerprint"),
        "llm_degraded": chain.get("llm_degraded"),
        "first_seen": chain.get("first_seen"),
        "last_seen": chain.get("last_seen"),
        "summary": chain.get("summary"),
    }


def _flatten_alert(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "alert_id": alert.get("alert_id"),
        "task_id": alert.get("task_id"),
        "chain_id": alert.get("chain_id"),
        "title": alert.get("title"),
        "severity": alert.get("severity"),
        "confidence": alert.get("confidence"),
        "risk_score": alert.get("risk_score"),
        "attacker_ips": alert.get("attacker_ips") or [],
        "victim_ips": alert.get("victim_ips") or [],
        "mitre_tactics": alert.get("mitre_tactics") or [],
        "mitre_techniques": alert.get("mitre_techniques") or [],
        "evidence_event_count": len(alert.get("evidence_event_ids") or []),
        "fingerprint": alert.get("fingerprint"),
        "status": alert.get("status"),
        "created_at": alert.get("created_at"),
        "llm_degraded": alert.get("llm_degraded"),
    }


def _flatten_entity(entity: dict[str, Any]) -> dict[str, Any]:
    return {
        "entity_id": entity.get("entity_id"),
        "entity_type": entity.get("entity_type"),
        "value": entity.get("value"),
        "role": entity.get("role"),
        "confidence": entity.get("confidence"),
        "chain_count": len(entity.get("chain_ids") or []),
        "chain_ids": entity.get("chain_ids") or [],
        "evidence_event_ids": entity.get("evidence_event_ids") or [],
        "tags": entity.get("tags") or [],
        "first_seen": entity.get("first_seen"),
        "last_seen": entity.get("last_seen"),
    }
