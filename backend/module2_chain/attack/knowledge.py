"""ATT&CK / behaviour knowledge base loader and deterministic matcher.

The knowledge base is data (``attack_kb.yaml``), never code: adding a technique
or a rule keyword must not require a code change.  Matching is fully
deterministic, which keeps Module 2 reproducible and testable without any LLM.

Keyword matching is *token aware*: short keywords such as ``rce`` or ``dos``
must appear as whole tokens, otherwise ``brute force`` would match ``rce``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from backend.module2_chain.app.logging import get_logger

logger = get_logger("attack.knowledge")

DEFAULT_KB_PATH = Path(__file__).parent / "knowledge" / "attack_kb.yaml"

_NORMALISE = re.compile(r"[^a-z0-9]+")

#: Keywords shorter than this must match a whole token.
_TOKEN_MATCH_MAX_LENGTH = 6


def normalise_text(value: str | None) -> str:
    """Lowercase and collapse separators so ``Port_Scan`` == ``port scan``."""

    if not value:
        return ""
    return _NORMALISE.sub(" ", value.lower()).strip()


def keyword_hit(keyword: str, haystack: str) -> bool:
    """Token-aware containment test.

    ``"rce"`` must not match ``"brute force"``; ``"exploit"`` may match
    ``"exploitation"``.
    """

    normalised = normalise_text(keyword)
    if not normalised or not haystack:
        return False
    if len(normalised) <= _TOKEN_MATCH_MAX_LENGTH:
        return f" {normalised} " in f" {haystack} "
    return normalised in haystack


@lru_cache(maxsize=4096)
def _normalised_keywords(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(normalise_text(value) for value in values if normalise_text(value))


class KnowledgeBaseError(RuntimeError):
    """Raised when the ATT&CK knowledge base cannot be loaded."""


class TacticDef(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    order: int = 0


class TechniqueDef(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    name: str
    tactic: str
    categories: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    detectors: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    base_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    requires_ioc: bool = False
    description: str = ""


class CategoryDef(BaseModel):
    model_config = ConfigDict(extra="allow")

    key: str
    label: str
    tactic: str
    severity_hint: str = "medium"
    keywords: list[str] = Field(default_factory=list)


@dataclass(slots=True)
class TechniqueSignals:
    """Aggregated, LLM-free signals of one attack candidate."""

    rules: list[str] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    ioc_hits: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    max_score: float = 0.0

    @property
    def rule_text(self) -> str:
        joined = " | ".join([*self.rules, *self.reasons, *self.detectors])
        return normalise_text(joined)

    @property
    def detector_text(self) -> str:
        return normalise_text(" | ".join(self.detectors))


@dataclass(slots=True)
class TechniqueMatch:
    """One deterministic technique candidate with its explanation."""

    technique: TechniqueDef
    tactic_id: str
    tactic_name: str
    confidence: float
    reason: str
    matched_rules: list[str] = field(default_factory=list)
    matched_signals: list[str] = field(default_factory=list)


class AttackKnowledgeBase(BaseModel):
    """Parsed ``attack_kb.yaml``."""

    model_config = ConfigDict(extra="allow")

    version: str = "1.0.0"
    description: str = ""
    tactic_order: list[str] = Field(default_factory=list)
    tactics: dict[str, TacticDef] = Field(default_factory=dict)
    categories: dict[str, CategoryDef] = Field(default_factory=dict)
    techniques: list[TechniqueDef] = Field(default_factory=list)

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #
    @classmethod
    def load(cls, path: str | Path | None = None) -> AttackKnowledgeBase:
        kb_path = Path(path) if path else DEFAULT_KB_PATH
        if not kb_path.is_file():
            raise KnowledgeBaseError(f"ATT&CK knowledge base not found: {kb_path}")
        raw = yaml.safe_load(kb_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise KnowledgeBaseError(f"knowledge base must be a mapping: {kb_path}")
        categories_raw = raw.get("categories") or {}
        categories = {
            key: CategoryDef(key=key, **value)
            for key, value in categories_raw.items()
            if isinstance(value, dict)
        }
        tactics_raw = raw.get("tactics") or {}
        tactics = {
            key: TacticDef(**value) for key, value in tactics_raw.items() if isinstance(value, dict)
        }
        techniques = [
            TechniqueDef(**item) for item in (raw.get("techniques") or []) if isinstance(item, dict)
        ]
        tactic_order = list(raw.get("tactic_order") or [])
        if not tactic_order:
            tactic_order = [tid for tid, _ in sorted(tactics.items(), key=lambda kv: kv[1].order)]
        return cls(
            version=str(raw.get("version", "1.0.0")),
            description=str(raw.get("description", "")),
            tactic_order=tactic_order,
            tactics=tactics,
            categories=categories,
            techniques=techniques,
        )

    # ------------------------------------------------------------------ #
    # Lookups
    # ------------------------------------------------------------------ #
    def tactic_name(self, tactic_id: str) -> str:
        tactic = self.tactics.get(tactic_id)
        return tactic.name if tactic else tactic_id

    def tactic_rank(self, tactic_id: str) -> int:
        """Position of a tactic in the canonical kill-chain order (0 = first)."""

        try:
            return self.tactic_order.index(tactic_id)
        except ValueError:
            tactic = self.tactics.get(tactic_id)
            return tactic.order if tactic else len(self.tactic_order)

    def technique(self, technique_id: str) -> TechniqueDef | None:
        for item in self.techniques:
            if item.id == technique_id:
                return item
        return None

    def technique_ids(self) -> set[str]:
        return {item.id for item in self.techniques}

    def category_label(self, key: str) -> str:
        definition = self.categories.get(key)
        return definition.label if definition else key

    def category_tactic(self, key: str) -> str | None:
        definition = self.categories.get(key)
        return definition.tactic if definition else None

    # ------------------------------------------------------------------ #
    # Classification / matching
    # ------------------------------------------------------------------ #
    def classify_category(
        self,
        text: str,
        *,
        detectors: list[str] | None = None,
        max_categories: int = 5,
    ) -> list[str]:
        """Return the behaviour categories implied by free text / detectors."""

        haystack = normalise_text(text)
        detector_haystack = normalise_text(" | ".join(detectors or []))
        scored: list[tuple[int, str]] = []
        for key, definition in self.categories.items():
            keywords = _normalised_keywords(tuple(definition.keywords))
            hits = sum(1 for keyword in keywords if keyword_hit(keyword, haystack))
            hits += sum(1 for keyword in keywords if keyword_hit(keyword, detector_haystack))
            if hits:
                scored.append((hits, key))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [key for _, key in scored[:max_categories]]

    def match_techniques(
        self,
        signals: TechniqueSignals,
        *,
        min_confidence: float = 0.3,
        max_results: int = 8,
    ) -> list[TechniqueMatch]:
        """Deterministically map candidate signals to ATT&CK techniques."""

        rule_text = signals.rule_text
        detector_text = signals.detector_text
        categories = {item.lower() for item in signals.categories}
        matches: list[TechniqueMatch] = []

        for technique in self.techniques:
            if technique.requires_ioc and not signals.ioc_hits:
                continue

            reasons: list[str] = []
            matched_signals: list[str] = []
            signal_factor = 0.0

            category_overlap = categories & {item.lower() for item in technique.categories}
            if category_overlap:
                signal_factor += 0.5
                matched_signals.extend(f"category:{item}" for item in sorted(category_overlap))
                reasons.append(f"behaviour category {', '.join(sorted(category_overlap))}")

            keywords = _normalised_keywords(tuple(technique.keywords))
            keyword_hits = [keyword for keyword in keywords if keyword_hit(keyword, rule_text)]
            if keyword_hits:
                signal_factor += min(0.45, 0.22 * len(keyword_hits))
                matched_signals.extend(f"keyword:{item}" for item in keyword_hits)
                reasons.append("rule/detector keywords: " + ", ".join(keyword_hits[:4]))

            detectors = _normalised_keywords(tuple(technique.detectors))
            detector_hits = [item for item in detectors if keyword_hit(item, detector_text)]
            if detector_hits:
                signal_factor += 0.3
                matched_signals.extend(f"detector:{item}" for item in detector_hits)
                reasons.append("detector: " + ", ".join(detector_hits[:3]))

            if signal_factor <= 0.0:
                continue

            confidence = technique.base_confidence * (0.5 + 0.5 * min(1.0, signal_factor))

            port_overlap = sorted(set(technique.ports) & set(signals.ports))
            if port_overlap:
                confidence += 0.08
                matched_signals.append("port:" + ",".join(str(port) for port in port_overlap))
                reasons.append("target ports " + ", ".join(str(port) for port in port_overlap))
            protocol_overlap = {item.lower() for item in technique.protocols} & {
                item.lower() for item in signals.protocols
            }
            if protocol_overlap:
                confidence += 0.04
                matched_signals.append("protocol:" + ",".join(sorted(protocol_overlap)))
            if signals.ioc_hits:
                confidence += 0.05
                reasons.append(f"{len(signals.ioc_hits)} IOC hit(s) on this candidate")

            confidence = round(min(0.98, confidence), 4)
            if confidence < min_confidence:
                continue

            matches.append(
                TechniqueMatch(
                    technique=technique,
                    tactic_id=technique.tactic,
                    tactic_name=self.tactic_name(technique.tactic),
                    confidence=confidence,
                    reason="; ".join(reasons) or "candidate signals matched knowledge base",
                    matched_rules=list(signals.rules),
                    matched_signals=matched_signals,
                )
            )

        matches.sort(key=lambda item: (-item.confidence, item.technique.id))
        return matches[:max_results]


@lru_cache(maxsize=8)
def _cached_kb(path: str) -> AttackKnowledgeBase:
    return AttackKnowledgeBase.load(path)


def load_knowledge_base(path: str | Path | None = None) -> AttackKnowledgeBase:
    """Cached knowledge-base accessor."""

    kb_path = Path(path) if path else DEFAULT_KB_PATH
    try:
        return _cached_kb(str(kb_path))
    except (KnowledgeBaseError, OSError, yaml.YAMLError) as exc:
        logger.error(
            "failed to load ATT&CK knowledge base",
            extra={"stage": "technique_mapping", "path": str(kb_path), "error": str(exc)},
        )
        raise KnowledgeBaseError(str(exc)) from exc


def knowledge_base_summary(kb: AttackKnowledgeBase) -> dict[str, Any]:
    return {
        "version": kb.version,
        "tactics": len(kb.tactics),
        "categories": len(kb.categories),
        "techniques": len(kb.techniques),
    }
