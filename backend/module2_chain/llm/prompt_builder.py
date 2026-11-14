"""AttackScenarioPromptBuilder - compact, token-bounded LLM prompts (M2-F11).

The model never sees raw payloads: only structured summaries of an aggregated
candidate plus the *candidate* ATT&CK set produced by the deterministic mapper.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.common.schemas.attack import AttackCandidate, CandidateTechnique, ThreatIntelRef
from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.llm.schemas import AttackAnalysisRequest

logger = get_logger("llm.prompt_builder")

SYSTEM_MARKER = "### SYSTEM"
USER_MARKER = "### USER"
DEFAULT_PROMPT_VERSION = "attack_analysis.v1"


class PromptError(RuntimeError):
    """Raised when a prompt template is missing or malformed."""


def render_template(template: str, values: dict[str, Any]) -> str:
    """Replace ``{{key}}`` placeholders without touching JSON braces."""

    rendered = template
    for key, value in values.items():
        rendered = rendered.replace(f"{{{{{key}}}}}", str(value))
    return rendered


class PromptTemplate:
    """A versioned system/user prompt pair."""

    def __init__(self, *, version: str, system: str, user: str) -> None:
        self.version = version
        self.system = system
        self.user = user

    @classmethod
    def load(cls, path: str | Path) -> PromptTemplate:
        prompt_path = Path(path)
        if not prompt_path.is_file():
            raise PromptError(f"prompt template not found: {prompt_path}")
        text = prompt_path.read_text(encoding="utf-8")
        return cls.parse(text, version=prompt_path.stem)

    @classmethod
    def parse(cls, text: str, *, version: str) -> PromptTemplate:
        if SYSTEM_MARKER not in text or USER_MARKER not in text:
            raise PromptError(
                f"prompt template must contain {SYSTEM_MARKER} and {USER_MARKER} sections"
            )
        _, _, after_system = text.partition(SYSTEM_MARKER)
        system_part, _, user_part = after_system.partition(USER_MARKER)
        system = system_part.strip()
        user = user_part.strip()
        if not system or not user:
            raise PromptError("prompt template sections must not be empty")
        return cls(version=version, system=system, user=user)

    def render_system(self, values: dict[str, Any]) -> str:
        return render_template(self.system, values)

    def render_user(self, values: dict[str, Any]) -> str:
        return render_template(self.user, values)


def load_prompt_template(
    prompt_dir: str | Path, version: str = DEFAULT_PROMPT_VERSION
) -> PromptTemplate:
    """Resolve ``attack_analysis.v1`` -> ``<dir>/attack_analysis.v1.txt``."""

    directory = Path(prompt_dir)
    for candidate in (directory / f"{version}.txt", directory / version):
        if candidate.is_file():
            template = PromptTemplate.load(candidate)
            return PromptTemplate(version=version, system=template.system, user=template.user)
    raise PromptError(f"no prompt template for version {version!r} in {directory}")


class AttackScenarioPromptBuilder:
    """Builds the provider-agnostic :class:`AttackAnalysisRequest`."""

    def __init__(self, config: AppConfig, *, template: PromptTemplate | None = None) -> None:
        self.config = config
        self.settings = config.llm
        self.template = template or load_prompt_template(
            config.prompt_dir, self.settings.prompt_version
        )

    # ------------------------------------------------------------------ #
    def build_evidence(
        self,
        candidate: AttackCandidate,
        events: list[SuspiciousEvent],
        *,
        event_index: dict[str, SuspiciousEvent] | None = None,
    ) -> list[dict[str, Any]]:
        """Compact per-event evidence (bounded by ``llm.max_input_events``)."""

        by_id = event_index or {event.event_id: event for event in events}
        ordered_ids = [event_id for event_id in candidate.event_ids if event_id in by_id]
        truncated = len(ordered_ids) > self.settings.max_input_events
        selected = ordered_ids[: self.settings.max_input_events]
        rows: list[dict[str, Any]] = []
        for event_id in selected:
            event = by_id[event_id]
            row: dict[str, Any] = {
                "event_id": event.event_id,
                "timestamp": event.event.timestamp.isoformat(),
                "src_ip": event.event.src_ip,
                "dst_ip": event.event.dst_ip,
                "dst_port": event.event.dst_port,
                "protocol": event.event.protocol,
                "matched_rules": event.detection.matched_rules[:8],
                "ioc_hits": event.detection.ioc_hits[:8],
                "score": round(float(event.detection.score or 0.0), 4),
                "detector": event.detection.detector,
                "session_id": event.session_id,
            }
            reason = (event.detection.reason or "").strip()
            if reason:
                row["reason"] = reason[:240]
            # Bridge-added M1 conclusions remain a distinct advisory field.
            extras = event.model_extra or {}
            semantic = {key: extras.get(key) for key in (
                "m1_semantic_verdict", "m1_semantic_attack_type", "m1_semantic_confidence", "m1_semantic_summary",
                "m1_semantic_provider", "m1_semantic_model", "m1_model_agreement",
                "m1_semantic_action", "m1_evidence_reference",
            ) if extras.get(key) not in (None, "", [])}
            if semantic:
                row["m1_semantic_assessment_advisory"] = semantic
            rows.append(row)
        if truncated:
            rows.append(
                {
                    "note": (
                        f"evidence truncated: {len(ordered_ids) - len(selected)} further "
                        "events of this candidate were omitted to control prompt size"
                    )
                }
            )
        return rows

    def build_candidate_summary(
        self,
        candidate: AttackCandidate,
        *,
        techniques: list[CandidateTechnique] | None = None,
        threat_intel: list[ThreatIntelRef] | None = None,
    ) -> dict[str, Any]:
        candidate_techniques = techniques if techniques is not None else candidate.techniques
        intelligence = threat_intel if threat_intel is not None else candidate.threat_intel
        return {
            "candidate_id": candidate.candidate_id,
            "task_id": candidate.task_id,
            "attacker_ips": candidate.attacker_ips[:10],
            "victim_ips": candidate.victim_ips[:20],
            "victim_ports": candidate.victim_ports[:20],
            "protocols": candidate.protocols[:8],
            "session_ids": candidate.session_ids[:10],
            "first_seen": candidate.first_seen.isoformat(),
            "last_seen": candidate.last_seen.isoformat(),
            "duration_seconds": round(candidate.duration_seconds, 3),
            "event_count": candidate.score_summary.event_count,
            "score_summary": {
                "max": round(candidate.score_summary.max_score, 4),
                "mean": round(candidate.score_summary.mean_score, 4),
                "p95": round(candidate.score_summary.p95_score, 4),
            },
            "rule_hits": candidate.rule_hits[:20],
            "ioc_hits": candidate.ioc_hits[:20],
            "behaviour_categories": candidate.attack_categories[:8],
            "correlation_score": candidate.correlation_score,
            "correlation_reasons": candidate.correlation_reasons[:8],
            "threat_intel": [
                {
                    "indicator": ref.indicator,
                    "indicator_type": ref.indicator_type,
                    "malicious": ref.malicious,
                    "confidence": ref.confidence,
                    "source": ref.source,
                    "tags": ref.tags[:6],
                }
                for ref in intelligence[:10]
            ],
            "candidate_techniques": [
                {
                    "tactic": item.tactic_id,
                    "tactic_name": item.tactic_name,
                    "technique": item.technique_id,
                    "technique_name": item.technique_name,
                    "confidence": item.confidence,
                    "reason": item.reason,
                    "evidence_event_ids": item.evidence_event_ids[:10],
                }
                for item in candidate_techniques[: self.config.attack.max_candidate_techniques]
            ],
        }

    def build(
        self,
        candidate: AttackCandidate,
        events: list[SuspiciousEvent],
        *,
        techniques: list[CandidateTechnique] | None = None,
        threat_intel: list[ThreatIntelRef] | None = None,
        event_index: dict[str, SuspiciousEvent] | None = None,
    ) -> AttackAnalysisRequest:
        """Assemble the full request (prompt + structured metadata)."""

        evidence = self.build_evidence(candidate, events, event_index=event_index)
        summary = self.build_candidate_summary(
            candidate, techniques=techniques, threat_intel=threat_intel
        )
        candidate_techniques = (
            techniques if techniques is not None else candidate.techniques
        )
        allowed_tactics = sorted({item.tactic_id for item in candidate_techniques}) or [
            "TA0001",
            "TA0002",
            "TA0006",
            "TA0007",
            "TA0008",
            "TA0011",
            "TA0010",
            "TA0040",
        ]
        allowed_techniques = sorted(
            {item.technique_id for item in candidate_techniques if item.technique_id}
        )

        values = {
            "prompt_version": self.template.version,
            "task_id": candidate.task_id,
            "candidate_id": candidate.candidate_id,
            "candidate_json": _json(summary),
            "allowed_tactics": ", ".join(allowed_tactics),
            "allowed_techniques": ", ".join(allowed_techniques) or "(none proposed)",
            "evidence_json": _json(evidence),
        }
        system_prompt = self.template.render_system(values)
        user_prompt = self.template.render_user(values)
        if len(user_prompt) > self.settings.max_evidence_chars:
            user_prompt = user_prompt[: self.settings.max_evidence_chars] + "\n...[truncated]"

        request = AttackAnalysisRequest(
            task_id=candidate.task_id,
            candidate_id=candidate.candidate_id,
            prompt_version=self.template.version,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            evidence_event_ids=list(candidate.event_ids),
            allowed_tactics=allowed_tactics,
            allowed_techniques=allowed_techniques,
            evidence_summary=summary,
            temperature=self.settings.temperature,
            max_output_tokens=self.settings.max_output_tokens,
            metadata={
                "candidate_techniques": [item.model_dump(mode="json") for item in candidate_techniques],
                "correlation_score": candidate.correlation_score,
                "attack_categories": list(candidate.attack_categories),
                "attacker_ips": list(candidate.attacker_ips),
                "victim_ips": list(candidate.victim_ips),
            },
        )
        logger.debug(
            "built attack scenario prompt",
            extra={
                "task_id": candidate.task_id,
                "candidate_id": candidate.candidate_id,
                "stage": "llm_prompt",
                "prompt_version": self.template.version,
                "prompt_chars": request.estimated_chars,
                "evidence_events": len(evidence),
            },
        )
        return request


def _json(payload: Any) -> str:
    import orjson

    return orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode("utf-8")
