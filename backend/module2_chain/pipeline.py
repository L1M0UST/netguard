"""Module 2 pipeline orchestration.

``Input -> Batch Validation -> Deduplication -> Normalization -> Temporal Window
-> Attacker/Victim Correlation -> Attack Session Clustering -> Threat Intel
-> Candidate ATT&CK Mapping -> LLM Reasoning -> Evidence Validation -> Chain
Construction -> Risk Scoring -> Confidence -> Fingerprint -> Event Dedup
-> Profiling -> Entity Extraction -> Report -> Bundle``

The pipeline is transport agnostic: it consumes a claimed ``04_m2_inbox`` folder
and publishes an ``05_m2_output`` bundle.  There is deliberately no HTTP/RPC/
queue code anywhere in Module 2.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from backend.common.schemas.attack import AttackCandidate, AttackChain
from backend.common.schemas.enums import Severity, TaskStatus
from backend.common.schemas.report import EvidenceSummary
from backend.common.schemas.status import BatchProgress
from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.lifecycle import CancellationToken, TaskCancelledError
from backend.module2_chain.app.logging import bind_context, get_logger, log_context
from backend.module2_chain.attack.candidate_builder import CandidateBuilder
from backend.module2_chain.attack.chain_builder import AttackChainBuilder
from backend.module2_chain.attack.deduplicator import AttackDeduplicator
from backend.module2_chain.attack.evidence_validator import EvidenceValidator
from backend.module2_chain.attack.fingerprint import AttackFingerprintBuilder
from backend.module2_chain.attack.knowledge import AttackKnowledgeBase, load_knowledge_base
from backend.module2_chain.attack.technique_mapper import AttackTechniqueMapper
from backend.module2_chain.correlation.engine import CorrelationEngine
from backend.module2_chain.entities.extractor import ThreatEntityExtractor
from backend.module2_chain.ingestion.batch_reader import BatchFormatError, BatchReader
from backend.module2_chain.ingestion.deduplicator import EventDeduplicator
from backend.module2_chain.ingestion.normalizer import EventNormalizer
from backend.module2_chain.ingestion.validator import BatchValidator
from backend.module2_chain.llm.base import LLMProvider
from backend.module2_chain.llm.factory import create_llm_provider
from backend.module2_chain.llm.invoker import InvocationResult, LLMInvoker
from backend.module2_chain.llm.prompt_builder import AttackScenarioPromptBuilder
from backend.module2_chain.llm.schemas import (
    AttackAnalysisRequest,
    LLMCallRecord,
    LLMThreatEntity,
)
from backend.module2_chain.persistence.registry import ProcessedRegistry
from backend.module2_chain.persistence.status_store import TaskStatusStore
from backend.module2_chain.profiling.attacker_profiler import AttackerProfiler
from backend.module2_chain.reporting.alert_builder import AlertBuilder
from backend.module2_chain.reporting.bundle_writer import BundlePayload, BundleWriter
from backend.module2_chain.reporting.report_builder import ReportBuilder
from backend.module2_chain.risk.scorer import RiskScorer, ScoringContext
from backend.module2_chain.scanner.claim import TaskClaimer
from backend.module2_chain.scanner.manifest import manifest_checksum
from backend.module2_chain.scanner.workspace_scanner import WorkspaceScanner
from backend.module2_chain.schemas.internal import (
    MetricsSnapshot,
    StageTiming,
    TaskOutcome,
    WorkspaceTaskDescriptor,
)
from backend.module2_chain.threat_intel.service import ThreatIntelService

logger = get_logger("pipeline")

#: Progress percentage per stage (spec §31: ``progress`` is 0-100).
PROGRESS: dict[str, float] = {
    "discovery": 2.0,
    "validation": 8.0,
    "ingestion": 18.0,
    "deduplication": 24.0,
    "normalization": 28.0,
    "correlation": 40.0,
    "threat_intel": 50.0,
    "technique_mapping": 55.0,
    "llm_analysis": 70.0,
    "evidence_validation": 76.0,
    "chain_building": 82.0,
    "risk_scoring": 86.0,
    "fingerprinting": 88.0,
    "event_deduplication": 90.0,
    "profiling": 93.0,
    "entity_extraction": 95.0,
    "report_generation": 97.0,
    "bundle_write": 99.0,
}


class TaskInputError(RuntimeError):
    """Task level failure that must abort the task (spec §47)."""


@dataclass(slots=True)
class _TaskTimer:
    """Sequential stage timer feeding ``metrics.json``."""

    timings: list[StageTiming] = field(default_factory=list)
    current_stage: str | None = None
    _started_at: float = 0.0

    def switch(self, stage: str, items: int | None = None) -> None:
        self.stop(items=items)
        self.current_stage = stage
        self._started_at = time.perf_counter()

    def stop(self, items: int | None = None) -> float:
        if self.current_stage is None:
            return 0.0
        duration_ms = (time.perf_counter() - self._started_at) * 1000.0
        self.timings.append(
            StageTiming(
                stage=self.current_stage, duration_ms=round(duration_ms, 3), items=items
            )
        )
        self.current_stage = None
        return duration_ms


class Module2Pipeline:
    """The Module 2 application (batch oriented, run-to-completion per task)."""

    def __init__(
        self,
        config: AppConfig,
        *,
        provider: LLMProvider | None = None,
        registry: ProcessedRegistry | None = None,
        knowledge: AttackKnowledgeBase | None = None,
    ) -> None:
        self.config = config
        self.knowledge = knowledge or load_knowledge_base(config.attack_kb_path)
        self.registry = registry or ProcessedRegistry(config)
        self.status_store = TaskStatusStore(config)
        self.scanner = WorkspaceScanner(config)
        self.claimer = TaskClaimer(config)
        self.validator = BatchValidator(config)
        self.reader = BatchReader(config, validator=self.validator)
        self.deduplicator = EventDeduplicator(config)
        self.normalizer = EventNormalizer(config)
        self.engine = CorrelationEngine(
            config, knowledge=self.knowledge, builder=CandidateBuilder(self.knowledge)
        )
        self.threat_intel = ThreatIntelService(config)
        self.technique_mapper = AttackTechniqueMapper(config, knowledge=self.knowledge)
        self.prompt_builder = AttackScenarioPromptBuilder(config)
        self.provider = provider or create_llm_provider(config)
        self.invoker = LLMInvoker(config, self.provider)
        self.evidence_validator = EvidenceValidator(config, knowledge=self.knowledge)
        self.chain_builder = AttackChainBuilder(config, knowledge=self.knowledge)
        self.fingerprints = AttackFingerprintBuilder(config)
        self.chain_deduplicator = AttackDeduplicator(config)
        self.scorer = RiskScorer(config, knowledge=self.knowledge)
        self.profiler = AttackerProfiler(config, knowledge=self.knowledge)
        self.entity_extractor = ThreatEntityExtractor(config)
        self.alert_builder = AlertBuilder(config)
        self.report_builder = ReportBuilder(config)
        self.bundle_writer = BundleWriter(config)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    async def run_once(
        self,
        *,
        max_tasks: int | None = None,
        task_ids: list[str] | None = None,
        force: bool = False,
        retry_failed: bool = False,
        token: CancellationToken | None = None,
    ) -> list[TaskOutcome]:
        """Process every claimable task folder once."""

        outcomes: list[TaskOutcome] = []
        descriptors = self._collect_descriptors(task_ids=task_ids, retry_failed=retry_failed)
        limit = len(descriptors) if task_ids else (max_tasks or len(descriptors))
        for descriptor in descriptors[:limit]:
            if token is not None and token.cancelled:
                break
            outcomes.append(await self.process_task(descriptor, force=force, token=token))
        await self.invoker.aclose()
        return outcomes

    async def process_task(
        self,
        descriptor: WorkspaceTaskDescriptor,
        *,
        force: bool = False,
        token: CancellationToken | None = None,
    ) -> TaskOutcome:
        task_id = descriptor.task_id
        timer = _TaskTimer()
        started = time.perf_counter()
        with log_context(task_id=task_id, stage="discovery"):
            claim = self.claimer.claim(descriptor, force=force)
            if not claim.claimed:
                logger.info(
                    "task was not claimed",
                    extra={"task_id": task_id, "stage": "claim", "reason": claim.reason},
                )
                return TaskOutcome(
                    task_id=task_id,
                    status=TaskStatus.PENDING,
                    skipped_reason=claim.reason,
                    idempotent_replay=True,
                )
            try:
                outcome = await self._run_claimed_task(descriptor, timer, token, force=force)
                duration_ms = (time.perf_counter() - started) * 1000.0
                logger.info(
                    "task finished",
                    extra={
                        "task_id": task_id,
                        "stage": "pipeline",
                        "status": str(outcome.status),
                        "duration_ms": round(duration_ms, 3),
                    },
                )
                # ``outcome.duration_ms`` is the full wall-clock time of the task,
                # while ``metrics.total_duration_ms`` covers the pipeline stages up
                # to (and excluding) the bundle write itself.
                return outcome.model_copy(update={"duration_ms": round(duration_ms, 3)})
            except TaskCancelledError as exc:
                self.status_store.cancel(task_id, reason=str(exc))
                self.claimer.release(task_id)
                return TaskOutcome(
                    task_id=task_id, status=TaskStatus.CANCELLED, errors=[str(exc)]
                )
            except TaskInputError as exc:
                self.claimer.release(task_id)
                return self._fail_task(descriptor, str(exc))
            except Exception as exc:  # pragma: no cover - defensive
                logger.error(
                    "task failed with an unexpected error",
                    extra={"task_id": task_id, "stage": "pipeline", "error": str(exc)},
                    exc_info=True,
                )
                self.claimer.release(task_id)
                return self._fail_task(descriptor, str(exc))

    async def aclose(self) -> None:
        self.claimer.release_all()
        self.registry.close()

    # ------------------------------------------------------------------ #
    # Task level helpers
    # ------------------------------------------------------------------ #
    def _collect_descriptors(
        self, *, task_ids: list[str] | None, retry_failed: bool
    ) -> list[WorkspaceTaskDescriptor]:
        states = [
            self.config.workspace.ready_marker,
            self.config.workspace.processing_marker,
        ]
        descriptors = self.scanner.scan(states=states, include_processed=False)
        if retry_failed:
            for descriptor in self.scanner.scan(states=[self.config.workspace.failed_marker]):
                self.claimer.requeue(descriptor)
                descriptors.append(self.scanner.describe(descriptor.task_dir))
        if task_ids:
            wanted = set(task_ids)
            descriptors = [item for item in descriptors if item.task_id in wanted]
            found_ids = {item.task_id for item in descriptors}
            for task_id in sorted(wanted - found_ids):
                found = self.scanner.find_task(task_id)
                if found is not None:
                    descriptors.append(found)
        return descriptors

    def _fail_task(self, descriptor: WorkspaceTaskDescriptor, error: str) -> TaskOutcome:
        task_id = descriptor.task_id
        self.status_store.fail(task_id, error=error)
        self.claimer.fail(task_id, descriptor.task_dir, error=error)
        self.registry.mark_task(task_id=task_id, status=str(TaskStatus.FAILED))
        return TaskOutcome(task_id=task_id, status=TaskStatus.FAILED, errors=[error])

    async def _run_claimed_task(
        self,
        descriptor: WorkspaceTaskDescriptor,
        timer: _TaskTimer,
        token: CancellationToken | None,
        *,
        force: bool,
    ) -> TaskOutcome:
        config = self.config
        task_id = descriptor.task_id
        warnings: list[str] = []
        candidate_failures: list[str] = []
        self.status_store.start(task_id, input_batches=len(descriptor.batch_files))

        # ---- M2-F2 batch validation ------------------------------------
        self._progress(task_id, "validation", timer)
        validation = self.validator.validate_descriptor(descriptor)
        input_checksum = self._input_checksum(descriptor, validation.manifest_checksum)
        if not validation.valid:
            errors = "; ".join(issue.message for issue in validation.errors[:5])
            raise TaskInputError(f"input validation failed: {errors}")
        warnings.extend(issue.message for issue in validation.warnings[:5])
        if not descriptor.batch_files:
            raise TaskInputError("task contains no batch files")

        replay = not force and self.registry.is_task_completed(task_id, input_checksum)
        if replay:
            self.claimer.complete(task_id, descriptor.task_dir)
            self.status_store.complete(
                task_id,
                output_path=str(self.config.output_dir / task_id),
                idempotent_replay=True,
            )
            return TaskOutcome(
                task_id=task_id,
                status=TaskStatus.COMPLETED,
                skipped_reason="already processed (idempotent replay)",
                idempotent_replay=True,
            )
        self.registry.mark_task(
            task_id=task_id, status="processing", input_checksum=input_checksum
        )
        self._check_cancel(token)

        # ---- M2-F1 ingestion -------------------------------------------
        self._progress(task_id, "ingestion", timer)
        try:
            ingestion = self.reader.read_task(descriptor)
        except BatchFormatError as exc:
            raise TaskInputError(str(exc)) from exc
        if not ingestion.events and config.ingestion.fail_on_empty_batch:
            raise TaskInputError("no usable suspicious events in the batch")
        for batch_id, rows in ingestion.batch_row_counts.items():
            self.registry.mark_batch(
                task_id=task_id, batch_id=batch_id, sha256=input_checksum, row_count=rows
            )
        self.status_store.set_batches(
            task_id,
            [
                BatchProgress(batch_id=batch_id, row_count=rows, status="processed")
                for batch_id, rows in ingestion.batch_row_counts.items()
            ],
        )
        self._check_cancel(token)

        # ---- M2-F3 deduplication + normalization -----------------------
        self._progress(task_id, "deduplication", timer)
        dedup_result = self.deduplicator.deduplicate(ingestion.events)
        self._progress(task_id, "normalization", timer)
        normalized = self.normalizer.normalize(dedup_result.events)
        events = normalized.events
        events_by_id = {event.event.event_id: event for event in events}
        if len(events) > config.app.max_events_per_task:
            raise TaskInputError(
                f"{len(events)} events exceed app.max_events_per_task="
                f"{config.app.max_events_per_task}"
            )
        self._check_cancel(token)

        # ---- M2-F4..F7 correlation -------------------------------------
        self._progress(task_id, "correlation", timer)
        candidates = self.engine.correlate(events)
        self.status_store.update(
            task_id, attack_candidates=len(candidates), current_stage="correlation"
        )
        self._check_cancel(token)

        # ---- M2-F8/F9/F10 threat intel + ATT&CK mapping ----------------
        self._progress(task_id, "threat_intel", timer)
        candidates_by_id: dict[str, AttackCandidate] = {}
        events_by_candidate: dict[str, list[SuspiciousEvent]] = {}
        for candidate in candidates:
            candidate_events = [
                events_by_id[event_id]
                for event_id in candidate.event_ids
                if event_id in events_by_id
            ]
            events_by_candidate[candidate.candidate_id] = candidate_events
            intel = self.threat_intel.enrich_candidate(candidate, candidate_events)
            candidate = candidate.model_copy(update={"threat_intel": intel})
            self._progress(task_id, "technique_mapping", timer)
            techniques, _signals = self.technique_mapper.map_candidate(
                candidate, candidate_events
            )
            candidates_by_id[candidate.candidate_id] = candidate.model_copy(
                update={"techniques": techniques}
            )
        self._check_cancel(token)

        # ---- M2-F11/F12 LLM reasoning (one call per candidate group) ----
        self._progress(task_id, "llm_analysis", timer)
        eligible: list[Any] = [
            candidate
            for candidate in candidates_by_id.values()
            if len(events_by_candidate[candidate.candidate_id]) >= config.llm.min_events_for_llm
        ]
        budget = int(config.llm.max_candidates or 0)
        if budget and len(eligible) > budget:
            # 预算内优先研判风险分最高、证据最多的候选；未入选者走规则降级链（fail_open 语义）。
            eligible.sort(
                key=lambda candidate: (
                    max(
                        (
                            float(event.detection.score)
                            for event in events_by_candidate[candidate.candidate_id]
                        ),
                        default=0.0,
                    ),
                    len(events_by_candidate[candidate.candidate_id]),
                ),
                reverse=True,
            )
            eligible = eligible[:budget]
            logger.info(
                "llm candidate budget applied",
                extra={
                    "stage": "llm_analysis",
                    "task_id": task_id,
                    "eligible": len(candidates_by_id),
                    "budget": budget,
                },
            )
        requests: list[AttackAnalysisRequest] = [
            self.prompt_builder.build(
                candidate,
                events_by_candidate[candidate.candidate_id],
                techniques=candidate.techniques,
                threat_intel=candidate.threat_intel,
            )
            for candidate in eligible
        ]
        invocation_results: list[InvocationResult] = (
            await self.invoker.analyze_batch(requests) if requests else []
        )
        results_by_candidate = {
            result.record.candidate_id: result for result in invocation_results
        }
        llm_records: list[LLMCallRecord] = [result.record for result in invocation_results]
        self.registry.record_llm_calls(llm_records)
        self.status_store.update(
            task_id,
            llm_calls=len(llm_records),
            llm_failures=sum(1 for record in llm_records if record.fallback_used),
            current_stage="evidence_validation",
        )
        self._check_cancel(token)

        # ---- M2-F13..F15 evidence validation, chain, risk --------------
        self._progress(task_id, "evidence_validation", timer)
        chains: list[AttackChain] = []
        llm_entities_by_chain: dict[str, list[LLMThreatEntity]] = {}
        validation_issue_count = 0
        dropped_evidence = 0
        for candidate in candidates_by_id.values():
            candidate_events = events_by_candidate[candidate.candidate_id]
            try:
                chain, llm_entities, issues, dropped = self._analyse_candidate(
                    candidate, candidate_events, results_by_candidate
                )
            except Exception as exc:  # pragma: no cover - per candidate isolation
                candidate_failures.append(f"{candidate.candidate_id}: {exc}")
                logger.error(
                    "candidate processing failed; continuing with the remaining candidates",
                    extra={
                        "task_id": task_id,
                        "candidate_id": candidate.candidate_id,
                        "stage": "chain_building",
                        "error": str(exc),
                    },
                )
                continue
            validation_issue_count += issues
            dropped_evidence += dropped
            chains.append(chain)
            if llm_entities:
                llm_entities_by_chain[chain.chain_id] = llm_entities

        # ---- M2-F16/F17 fingerprint + attack event deduplication -------
        self._progress(task_id, "event_deduplication", timer)
        unique_chains, merged_away = self.chain_deduplicator.deduplicate(chains)
        known_external = self.registry.known_fingerprints(exclude_task=task_id)
        for chain in unique_chains:
            if chain.fingerprint and chain.fingerprint in known_external:
                warnings.append(
                    f"fingerprint {chain.fingerprint} was already reported by another task"
                )

        # ---- M2-F18/F27 profiling + entity extraction ------------------
        self._progress(task_id, "profiling", timer)
        profiles = self.profiler.profile(task_id, unique_chains, events_by_id)
        self._progress(task_id, "entity_extraction", timer)
        entities, chain_entities = self.entity_extractor.extract(
            task_id, unique_chains, events_by_id, llm_entities=llm_entities_by_chain
        )
        unique_chains = [
            chain.model_copy(update={"threat_entities": chain_entities.get(chain.chain_id, [])})
            for chain in unique_chains
        ]

        # ---- M2-F19/F20 report + bundle --------------------------------
        self._progress(task_id, "report_generation", timer)
        alerts = self.alert_builder.build_many(unique_chains)
        metrics_snapshot = self._metrics(
            task_id=task_id,
            timer=timer,
            ingestion_rows=ingestion.raw_row_count,
            deduplicated=dedup_result.dropped_count,
            unique_events=len(events),
            chains=unique_chains,
            candidates=len(candidates_by_id),
            alerts=len(alerts),
            llm_records=llm_records,
        )
        events_in_chains = {
            event_id for chain in unique_chains for event_id in chain.event_ids
        }
        evidence_summary = EvidenceSummary(
            total_input_events=ingestion.raw_row_count,
            unique_events=len(events),
            events_in_chains=len(events_in_chains),
            events_without_chain=max(0, len(events) - len(events_in_chains)),
            candidate_count=len(candidates_by_id),
            dropped_llm_evidence=dropped_evidence,
            validation_issues=validation_issue_count,
            per_stage={
                "ingested": ingestion.raw_row_count,
                "deduplicated": len(dedup_result.events),
                "candidates": len(candidates_by_id),
                "chains": len(unique_chains),
                "merged_chains": len(merged_away),
            },
        )
        report = self.report_builder.build(
            task_id=task_id,
            chains=unique_chains,
            alerts=alerts,
            profiles=profiles,
            entities=entities,
            evidence_summary=evidence_summary,
            total_suspicious_events=ingestion.raw_row_count,
            deduplicated_events=dedup_result.dropped_count,
            candidate_count=len(candidates_by_id),
            metrics=metrics_snapshot.model_dump(mode="json"),
            llm_meta=self.invoker.summary(),
            warnings=warnings,
        )
        self._progress(task_id, "bundle_write", timer)
        bundle = self.bundle_writer.write(
            BundlePayload(
                task_id=task_id,
                chains=unique_chains,
                alerts=alerts,
                attackers=profiles,
                entities=entities,
                report=report,
                metrics=metrics_snapshot.model_dump(mode="json"),
                evidence={
                    chain.chain_id: {
                        "event_ids": chain.event_ids,
                        "evidence_event_ids": chain.all_evidence_event_ids(),
                        "validation": chain.evidence_validation,
                        "uncertainties": chain.uncertainties,
                    }
                    for chain in unique_chains
                },
                input_batches=list(ingestion.batch_row_counts),
                input_checksums=[input_checksum] if input_checksum else [],
                run={
                    "started_at": metrics_snapshot.started_at.isoformat(),
                    "finished_at": (
                        metrics_snapshot.finished_at.isoformat()
                        if metrics_snapshot.finished_at
                        else None
                    ),
                    "duration_ms": metrics_snapshot.total_duration_ms,
                    "llm": self.invoker.summary(),
                    "provider": self.provider.name,
                    "model": self.provider.model,
                    "prompt_version": config.llm.prompt_version,
                    "knowledge_base": self.knowledge.version,
                    "force": force,
                },
            )
        )

        # ---- M2-F21..F23 status, registry, markers ---------------------
        self.registry.record_fingerprints(task_id, unique_chains)
        self.registry.mark_task(
            task_id=task_id,
            status="completed",
            input_checksum=input_checksum,
            output_path=str(bundle.bundle_dir),
            attack_events=len(unique_chains),
            attack_candidates=len(candidates_by_id),
        )
        counts = {
            "processed_batches": len(ingestion.batch_row_counts),
            "attack_candidates": len(candidates_by_id),
            "attack_events": len(unique_chains),
            "llm_calls": len(llm_records),
            "llm_failures": sum(1 for record in llm_records if record.fallback_used),
        }
        self.status_store.complete(
            task_id,
            output_path=str(bundle.bundle_dir),
            counts=counts,
            metrics=metrics_snapshot.model_dump(mode="json"),
        )
        self.claimer.complete(task_id, descriptor.task_dir)

        worst = max(
            (chain.severity for chain in unique_chains), key=lambda item: item.rank, default=None
        )
        return TaskOutcome(
            task_id=task_id,
            status=TaskStatus.COMPLETED,
            chain_ids=[chain.chain_id for chain in unique_chains],
            alert_ids=[alert.alert_id for alert in alerts],
            attacker_ids=[profile.attacker_id for profile in profiles],
            entity_count=len(entities),
            candidate_count=len(candidates_by_id),
            event_count=len(events),
            badge=worst or Severity.INFO,
            bundle_path=bundle.bundle_dir,
            report_path=bundle.bundle_dir / "reports" / "report.json",
            metrics=metrics_snapshot,
            warnings=[*warnings, *candidate_failures],
            duration_ms=metrics_snapshot.total_duration_ms,
        )

    # ------------------------------------------------------------------ #
    def _analyse_candidate(
        self,
        candidate: AttackCandidate,
        candidate_events: list[SuspiciousEvent],
        results_by_candidate: dict[str, InvocationResult],
    ) -> tuple[AttackChain, list[LLMThreatEntity], int, int]:
        """Validate, build, score and fingerprint one candidate."""

        result = results_by_candidate.get(candidate.candidate_id)
        analysis = result.analysis if result else None
        record = result.record if result else None
        validation = None
        issue_count = 0
        dropped = 0
        if analysis is not None:
            analysis, validation = self.evidence_validator.validate(
                candidate, analysis, candidate_events, candidate.techniques
            )
            issue_count = len(validation.issues)
            dropped = len(validation.unknown_event_ids)
        chain = self.chain_builder.build(
            candidate,
            candidate_events,
            analysis=analysis,
            validation=validation,
            techniques=candidate.techniques,
            llm_record=record,
        )
        malicious = sum(
            1
            for ref in candidate.threat_intel
            if ref.malicious and ref.confidence >= self.config.threat_intel.min_confidence
        )
        chain = chain.model_copy(
            update={
                "evidence_validation": {
                    **chain.evidence_validation,
                    "ioc_hits": [ref.indicator for ref in candidate.threat_intel],
                    "malicious_ioc_hits": malicious,
                    "rules": list(candidate.rule_hits),
                    "candidate_id": candidate.candidate_id,
                }
            }
        )
        context = ScoringContext(
            candidate=candidate,
            events=candidate_events,
            analysis=analysis,
            validation=validation,
            ioc_hits=len(candidate.threat_intel),
            malicious_ioc_hits=malicious,
        )
        chain = self.scorer.apply(chain, context)
        chain = self.fingerprints.apply(chain)
        entities = list(analysis.threat_entities) if analysis else []
        return chain, entities, issue_count, dropped

    def _metrics(
        self,
        *,
        task_id: str,
        timer: _TaskTimer,
        ingestion_rows: int,
        deduplicated: int,
        unique_events: int,
        chains: list[AttackChain],
        candidates: int,
        alerts: int,
        llm_records: list[LLMCallRecord],
    ) -> MetricsSnapshot:
        timer.stop()
        total_duration_ms = sum(timing.duration_ms for timing in timer.timings)
        llm_summary = self.invoker.summary()
        return MetricsSnapshot(
            task_id=task_id,
            finished_at=datetime.now(UTC),
            total_duration_ms=round(total_duration_ms, 3),
            stage_timings=list(timer.timings),
            events_ingested=ingestion_rows,
            events_deduplicated=deduplicated,
            events_unique=unique_events,
            events_in_chains=len({event_id for chain in chains for event_id in chain.event_ids}),
            candidates=candidates,
            chains=len(chains),
            alerts=alerts,
            llm_calls=len(llm_records),
            llm_failures=sum(1 for record in llm_records if record.fallback_used),
            llm_tokens_input=int(llm_summary.get("input_tokens") or 0),
            llm_tokens_output=int(llm_summary.get("output_tokens") or 0),
            llm_latency_p50_ms=llm_summary.get("latency_p50_ms"),
            llm_latency_p95_ms=llm_summary.get("latency_p95_ms"),
            llm_latency_p99_ms=llm_summary.get("latency_p99_ms"),
            events_per_second=_rate(unique_events, total_duration_ms),
            candidates_per_second=_rate(candidates, total_duration_ms),
            llm_calls_per_candidate=round(len(llm_records) / candidates, 4) if candidates else 0.0,
            llm_call_ratio=round(len(llm_records) / unique_events, 6) if unique_events else 0.0,
            peak_memory_mb=_peak_memory_mb(),
            extra={
                "llm": llm_summary,
                "threat_intel": self.threat_intel.health(),
                "provider": self.provider.name,
                "model": self.provider.model,
                "prompt_version": self.config.llm.prompt_version,
                "knowledge_base": self.knowledge.version,
            },
        )

    def _progress(self, task_id: str, stage: str, timer: _TaskTimer) -> None:
        timer.switch(stage)
        bind_context(task_id=task_id, stage=stage)
        self.status_store.update(
            task_id, progress=PROGRESS.get(stage, 50.0), current_stage=stage
        )

    @staticmethod
    def _check_cancel(token: CancellationToken | None) -> None:
        if token is not None:
            token.raise_if_cancelled()

    @staticmethod
    def _input_checksum(
        descriptor: WorkspaceTaskDescriptor, manifest_digest: str | None
    ) -> str | None:
        if manifest_digest:
            return manifest_digest
        if descriptor.manifest_path and descriptor.manifest_path.is_file():
            try:
                payload = json.loads(descriptor.manifest_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return None
            return manifest_checksum(payload)
        if descriptor.batch_files:
            return manifest_checksum(
                {
                    "task_id": descriptor.task_id,
                    "files": [path.name for path in descriptor.batch_files],
                    "sizes": [path.stat().st_size for path in descriptor.batch_files],
                }
            )
        return None


def _rate(items: int, duration_ms: float) -> float:
    if duration_ms <= 0:
        return 0.0
    return round(items / (duration_ms / 1000.0), 3)


def _peak_memory_mb() -> float | None:
    try:
        import resource
    except ImportError:  # pragma: no cover - non POSIX
        return None
    usage = resource.getrusage(resource.RUSAGE_SELF)
    if usage.ru_maxrss <= 0:
        return None
    return round(usage.ru_maxrss / 1024.0, 2)
