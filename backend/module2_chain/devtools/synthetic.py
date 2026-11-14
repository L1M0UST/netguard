"""Deterministic ``SuspiciousEventBatch.v1`` generator.

Covers the eight attack scenarios required by the acceptance criteria: scanning,
brute force, exploitation, malicious communication, command execution, lateral
movement, exfiltration and impact.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import polars as pl

from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.common.schemas.version import SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION
from backend.module2_chain.reporting.atomic_io import atomic_write_bytes, atomic_write_json
from backend.module2_chain.scanner.manifest import build_file_ref, manifest_checksum

BASE_TIME = datetime(2024, 5, 1, 12, 0, 0, tzinfo=UTC)


@dataclass(slots=True)
class ScenarioSpec:
    """Recipe for one synthetic attack scenario."""

    key: str
    rules: tuple[str, ...]
    detectors: tuple[str, ...]
    reasons: tuple[str, ...]
    ports: tuple[int, ...]
    protocols: tuple[str, ...] = ("tcp",)
    ioc_hits: tuple[str, ...] = ()
    score_range: tuple[float, float] = (45.0, 80.0)
    victims: int = 1
    events_per_victim: int = 3


SCENARIOS: dict[str, ScenarioSpec] = {
    "scanning": ScenarioSpec(
        key="scanning",
        rules=("l1_port_scan_sweep", "l1_service_discovery"),
        detectors=("scan_detector",),
        reasons=("nmap style port scan across many destination ports",),
        ports=(21, 22, 23, 80, 139, 443, 445, 3389, 8080),
        victims=4,
        events_per_victim=3,
        score_range=(35.0, 60.0),
    ),
    "brute_force": ScenarioSpec(
        key="brute_force",
        rules=("l1_brute_force_ssh", "l1_auth_failure_burst"),
        detectors=("auth_analyzer",),
        reasons=("repeated failed login attempts user=admin",),
        ports=(22, 3389),
        victims=1,
        events_per_victim=6,
        score_range=(55.0, 75.0),
    ),
    "exploitation": ScenarioSpec(
        key="exploitation",
        rules=("l1_exploit_cve_2021_44228", "l1_webshell_upload"),
        detectors=("signature_engine",),
        reasons=("CVE-2021-44228 exploitation attempt against /api/login",),
        ports=(80, 8080),
        ioc_hits=("CVE-2021-44228",),
        victims=1,
        events_per_victim=3,
        score_range=(80.0, 95.0),
    ),
    "malicious_communication": ScenarioSpec(
        key="malicious_communication",
        rules=("l1_c2_beacon_periodic", "l1_malicious_domain_dns"),
        detectors=("beacon_detector",),
        reasons=("periodic beacon to evil-c2.example.com every 60s",),
        ports=(443, 53),
        ioc_hits=("evil-c2.example.com", "203.0.113.66"),
        victims=1,
        events_per_victim=4,
        score_range=(70.0, 90.0),
    ),
    "command_execution": ScenarioSpec(
        key="command_execution",
        rules=("l1_suspicious_powershell", "l1_encoded_command"),
        detectors=("process_monitor",),
        reasons=("powershell -enc executing encoded staged payload",),
        ports=(445, 5985),
        victims=1,
        events_per_victim=2,
        score_range=(75.0, 92.0),
    ),
    "lateral_movement": ScenarioSpec(
        key="lateral_movement",
        rules=("l1_smb_psexec_lateral", "l1_remote_service_creation"),
        detectors=("smb_monitor",),
        reasons=("psexec style service creation over SMB to internal host",),
        ports=(445, 135),
        victims=3,
        events_per_victim=2,
        score_range=(85.0, 96.0),
    ),
    "exfiltration": ScenarioSpec(
        key="exfiltration",
        rules=("l1_data_exfil_upload", "l1_large_outbound_transfer"),
        detectors=("flow_analyzer",),
        reasons=("2.4GB outbound upload to external storage service",),
        ports=(443, 8443),
        ioc_hits=("198.51.100.23",),
        victims=1,
        events_per_victim=2,
        score_range=(85.0, 97.0),
    ),
    "impact": ScenarioSpec(
        key="impact",
        rules=("l1_ransomware_encryption", "l1_shadow_copy_deletion"),
        detectors=("endpoint_monitor",),
        reasons=("mass file encryption and ransom note creation",),
        ports=(445,),
        victims=2,
        events_per_victim=2,
        score_range=(92.0, 100.0),
    ),
}

ATTACKER_POOL: tuple[str, ...] = (
    "10.0.0.8",
    "10.0.0.9",
    "10.0.7.31",
    "172.16.4.12",
    "203.0.113.45",
)

VICTIM_POOL: tuple[str, ...] = (
    "10.0.0.12",
    "10.0.0.13",
    "10.0.0.21",
    "10.0.5.44",
    "10.0.9.7",
)


@dataclass(slots=True)
class ScenarioEvents:
    """Synthetic events of one scenario, grouped by attacker."""

    scenario: str
    attacker: str
    events: list[SuspiciousEvent] = field(default_factory=list)


def _digest(*parts: object) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


def build_events(
    scenario: str,
    *,
    task_id: str = "task_demo",
    attacker: str | None = None,
    start: datetime = BASE_TIME,
    seed: int = 7,
    event_counter: list[int] | None = None,
) -> ScenarioEvents:
    """Build the events of one synthetic scenario."""

    spec = SCENARIOS[scenario]
    rng = random.Random(f"{scenario}:{seed}")
    attacker_ip = attacker or rng.choice(ATTACKER_POOL)
    counter = event_counter if event_counter is not None else [0]
    victims = rng.sample(VICTIM_POOL, k=min(spec.victims, len(VICTIM_POOL)))
    events: list[SuspiciousEvent] = []
    timestamp = start

    for victim_index, victim in enumerate(victims):
        for index in range(spec.events_per_victim):
            counter[0] += 1
            timestamp = timestamp + timedelta(seconds=rng.randint(5, 45))
            port = spec.ports[index % len(spec.ports)]
            protocol = spec.protocols[index % len(spec.protocols)]
            score = round(rng.uniform(*spec.score_range), 2)
            event_id = f"evt_{counter[0]:06d}"
            events.append(
                SuspiciousEvent.model_validate(
                    {
                        "event": {
                            "event_id": event_id,
                            "task_id": task_id,
                            "timestamp": timestamp,
                            "src_ip": attacker_ip,
                            "dst_ip": victim,
                            "src_port": rng.randint(30000, 65000),
                            "dst_port": port,
                            "protocol": protocol,
                            "payload_digest": _digest(event_id, scenario, victim_index),
                            "raw_ref": f"raw/{task_id}/{scenario}_{counter[0]:06d}.pcap#frame",
                            "source_file": f"{scenario}_capture.pcap",
                        },
                        "detection": {
                            "matched_rules": list(spec.rules[: 1 + (index % len(spec.rules))]),
                            "ioc_hits": list(spec.ioc_hits),
                            "score": score,
                            "reason": spec.reasons[index % len(spec.reasons)],
                            "detector": spec.detectors[index % len(spec.detectors)],
                        },
                        "session_id": f"sess_{scenario}_{victim_index:02d}",
                        "emitted_at": start,
                        "schema_version": SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION,
                    }
                )
            )
    return ScenarioEvents(scenario=scenario, attacker=attacker_ip, events=events)


def build_mixed_batch(
    *,
    task_id: str = "task_demo",
    scenarios: list[str] | None = None,
    seed: int = 7,
) -> list[SuspiciousEvent]:
    """One attacker per scenario, so correlation is deterministic."""

    selected = scenarios or list(SCENARIOS)
    counter = [0]
    events: list[SuspiciousEvent] = []
    for index, scenario in enumerate(selected):
        attacker = ATTACKER_POOL[index % len(ATTACKER_POOL)]
        result = build_events(
            scenario,
            task_id=task_id,
            attacker=attacker,
            start=BASE_TIME + timedelta(minutes=index),
            seed=seed,
            event_counter=counter,
        )
        events.extend(result.events)
    events.sort(key=lambda event: event.event.timestamp)
    return events


def build_events_for_count(
    count: int, *, task_id: str = "task_perf", seed: int = 11
) -> list[SuspiciousEvent]:
    """Build ``count`` events spread over the synthetic scenarios."""

    scenarios = list(SCENARIOS)
    events: list[SuspiciousEvent] = []
    counter = [0]
    index = 0
    while len(events) < count:
        scenario = scenarios[index % len(scenarios)]
        # One distinct source address per group keeps the load test realistic:
        # otherwise every group would chain onto the previous one and collapse
        # into a single giant candidate.
        attacker = f"198.18.{index // 250}.{(index % 250) + 1}"
        produced = build_events(
            scenario,
            task_id=task_id,
            attacker=attacker,
            start=BASE_TIME + timedelta(minutes=index),
            seed=seed + index,
            event_counter=counter,
        )
        events.extend(produced.events)
        index += 1
    events = events[:count]
    events.sort(key=lambda event: event.event.timestamp)
    return events


def build_batch(
    events: list[SuspiciousEvent],
    *,
    task_id: str = "task_demo",
    batch_id: str = "batch_000001",
    producer: str = "module1_fake",
    created_at: datetime | None = None,
) -> dict[str, object]:
    """Manifest payload for a synthetic batch (written by :func:`write_batch`)."""

    return {
        "schema_version": SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION,
        "task_id": task_id,
        "batch_id": batch_id,
        "producer": producer,
        "created_at": (created_at or BASE_TIME).isoformat(),
        "event_count": len(events),
    }


def write_batch(
    directory: str | Path,
    events: list[SuspiciousEvent],
    *,
    task_id: str = "task_demo",
    batch_id: str = "batch_000001",
    file_name: str = "batch_000001.parquet",
    ready: bool = True,
    producer: str = "module1_fake",
    created_at: datetime | None = None,
) -> Path:
    """Write a complete, contract-compliant ``SuspiciousEventBatch.v1`` folder.

    The writer follows the same protocol Module 1 must follow: temp file ->
    fsync -> sha256 -> rename -> ``READY`` last.
    """

    task_dir = Path(directory) / task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    rows = [event.to_flat_dict() for event in events]
    frame = pl.DataFrame(rows, infer_schema_length=None) if rows else _empty_frame()

    payload_path = task_dir / file_name
    temp_path = payload_path.with_name(payload_path.name + ".tmp")
    frame.write_parquet(temp_path)
    data = temp_path.read_bytes()
    atomic_write_bytes(payload_path, data)
    temp_path.unlink(missing_ok=True)

    file_ref = build_file_ref(payload_path, task_dir, row_count=len(events))
    manifest = {
        **build_batch(events, task_id=task_id, batch_id=batch_id, producer=producer,
                      created_at=created_at),
        "files": [file_ref.model_dump(mode="json")],
        "metadata": {"generator": "module2_chain.devtools.synthetic"},
    }
    manifest["checksum"] = manifest_checksum(manifest)
    atomic_write_json(task_dir / "manifest.json", manifest)
    if ready:
        atomic_write_json(
            task_dir / "READY",
            {"task_id": task_id, "batch_id": batch_id, "created_at": datetime.now(UTC).isoformat()},
        )
    return task_dir


def _empty_frame() -> pl.DataFrame:
    return pl.DataFrame(
        schema={
            "event.event_id": pl.Utf8,
            "event.task_id": pl.Utf8,
            "event.timestamp": pl.Datetime("us"),
            "event.src_ip": pl.Utf8,
            "event.dst_ip": pl.Utf8,
            "event.src_port": pl.Int64,
            "event.dst_port": pl.Int64,
            "event.protocol": pl.Utf8,
            "event.payload_digest": pl.Utf8,
            "event.raw_ref": pl.Utf8,
            "event.source_file": pl.Utf8,
            "detection.matched_rules": pl.List(pl.Utf8),
            "detection.ioc_hits": pl.List(pl.Utf8),
            "detection.score": pl.Float64,
            "detection.reason": pl.Utf8,
            "detection.detector": pl.Utf8,
            "session_id": pl.Utf8,
            "emitted_at": pl.Datetime("us"),
            "schema_version": pl.Utf8,
        }
    )


def write_json_batch(
    directory: str | Path,
    events: list[SuspiciousEvent],
    *,
    task_id: str = "task_demo",
) -> Path:
    """Write the same batch as JSON (used by fixtures and comparisons)."""

    task_dir = Path(directory) / task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    payload = [json.loads(event.model_dump_json()) for event in events]
    atomic_write_json(task_dir / "events.json", payload)
    return task_dir
