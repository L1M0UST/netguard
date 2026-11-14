"""Mitigation recommendations (spec §29).

Recommendations are split into:

* ``evidence_based`` - directly supported by the chain (e.g. an exploited CVE
  observed in the evidence, or a malicious indicator that was matched);
* ``general_recommendation`` - generic hardening advice for the observed
  technique, explicitly marked as such so downstream UIs can render it
  differently.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from backend.common.schemas.attack import AttackChain
from backend.common.schemas.enums import MitigationKind
from backend.common.schemas.report import Mitigation
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.attack.knowledge import AttackKnowledgeBase, load_knowledge_base
from backend.module2_chain.entities.patterns import extract_cves

MAX_MITIGATIONS_PER_CHAIN = 6


@dataclass(slots=True)
class MitigationTemplate:
    """One technique-driven remediation recipe."""

    title: str
    description: str
    priority: str = "medium"
    kind: MitigationKind = MitigationKind.GENERAL_RECOMMENDATION


#: Technique driven remediation knowledge (data, not business logic).
TECHNIQUE_MITIGATIONS: dict[str, MitigationTemplate] = {
    "T1190": MitigationTemplate(
        title="Patch the exploited public-facing service",
        description=(
            "The evidence references exploitation of an internet-facing service "
            "(matched rules: {rules}{cves}). Patch the affected component, remove the "
            "affected version from exposure and verify the vulnerability is no longer "
            "reachable."
        ),
        priority="critical",
        kind=MitigationKind.EVIDENCE_BASED,
    ),
    "T1110": MitigationTemplate(
        title="Enable MFA and rate limiting for authentication",
        description=(
            "Repeated authentication failures were observed on {ports}. Enforce MFA, "
            "account lockout / rate limiting and block a source after a bounded number "
            "of failures."
        ),
        priority="high",
    ),
    "T1046": MitigationTemplate(
        title="Restrict and monitor internal reconnaissance",
        description=(
            "Service/port scanning was detected. Segment the network, restrict "
            "east-west traffic to required flows and alert on scan-like patterns."
        ),
        priority="medium",
    ),
    "T1595": MitigationTemplate(
        title="Reduce the externally visible attack surface",
        description=(
            "Active scanning against exposed services was observed. Remove unneeded "
            "exposed ports, rate limit inbound connection attempts and feed scan "
            "sources into perimeter blocking."
        ),
        priority="medium",
    ),
    "T1059": MitigationTemplate(
        title="Constrain command and scripting interpreters",
        description=(
            "Command interpreter activity was observed. Restrict interpreter use to "
            "approved administrative paths, enable script block logging and alert on "
            "encoded or obfuscated command lines."
        ),
        priority="high",
    ),
    "T1003": MitigationTemplate(
        title="Protect credential stores",
        description=(
            "Credential dumping behaviour was observed. Enable credential guard / LSASS "
            "protection, restrict debugging privileges and rotate any credentials that "
            "may have been exposed."
        ),
        priority="critical",
    ),
    "T1021": MitigationTemplate(
        title="Restrict remote administration paths",
        description=(
            "Remote service usage (SMB/RDP/WinRM/SSH) was observed between hosts. Limit "
            "remote administration to jump hosts, require MFA and monitor lateral "
            "authentication."
        ),
        priority="high",
    ),
    "T1071": MitigationTemplate(
        title="Block and inspect command-and-control channels",
        description=(
            "Possible C2/beaconing behaviour was observed. Sinkhole or block the "
            "identified infrastructure, enable TLS inspection for egress and review "
            "scheduled outbound flows for beaconing periodicity."
        ),
        priority="high",
    ),
    "T1078": MitigationTemplate(
        title="Review account usage and access policy",
        description=(
            "Valid-account abuse is suspected. Review recent logins for the involved "
            "accounts, enforce least privilege and rotate credentials used from "
            "unexpected sources."
        ),
        priority="high",
    ),
    "T1105": MitigationTemplate(
        title="Control the ingress of tooling and second-stage payloads",
        description=(
            "Tool or payload transfer was observed. Restrict outbound downloads, block "
            "unauthorised file transfer services and inspect proxy logs."
        ),
        priority="medium",
    ),
    "T1567": MitigationTemplate(
        title="Apply egress data-loss controls",
        description=(
            "Outbound data transfer was observed. Apply DLP/egress filtering, limit "
            "upload destinations and alert on anomalous volume."
        ),
        priority="critical",
    ),
    "T1041": MitigationTemplate(
        title="Inspect command-and-control exfiltration channels",
        description=(
            "Exfiltration over a command-and-control channel is suspected. Block the "
            "channel, capture flow metadata and verify what data left the network."
        ),
        priority="critical",
    ),
    "T1048": MitigationTemplate(
        title="Monitor alternative-protocol egress",
        description=(
            "Exfiltration over an alternative protocol (DNS/ICMP/...) is suspected. "
            "Enforce DNS egress control, inspect ICMP volume and restrict unauthorised "
            "protocols at the perimeter."
        ),
        priority="high",
    ),
    "T1486": MitigationTemplate(
        title="Protect backups and prepare ransomware containment",
        description=(
            "Data-encryption-for-impact behaviour was observed. Validate offline "
            "backups, isolate affected hosts and disable the accounts used by the "
            "ransomware stage."
        ),
        priority="critical",
    ),
    "T1498": MitigationTemplate(
        title="Apply volumetric denial-of-service protection",
        description=(
            "Network flooding was observed. Enable upstream scrubbing / rate limits and "
            "block the involved sources."
        ),
        priority="high",
    ),
    "T1082": MitigationTemplate(
        title="Monitor host information discovery",
        description=(
            "System information discovery was observed. Alert on discovery commands "
            "issued from non-administrative contexts."
        ),
        priority="low",
    ),
    "T1547": MitigationTemplate(
        title="Audit autostart persistence locations",
        description=(
            "Autostart/persistence activity was observed. Audit autorun keys, startup "
            "folders and scheduled tasks on the affected hosts."
        ),
        priority="high",
    ),
    "T1562": MitigationTemplate(
        title="Protect security controls from tampering",
        description=(
            "Attempts to impair defences were observed. Enable tamper protection, "
            "forward security logs off-host and restrict who can stop sensors."
        ),
        priority="high",
    ),
}


class MitigationLibrary:
    """Turns chains into evidence-bounded :class:`Mitigation` objects."""

    def __init__(
        self, config: AppConfig, *, knowledge: AttackKnowledgeBase | None = None
    ) -> None:
        self.config = config
        self.knowledge = knowledge or load_knowledge_base(config.attack_kb_path)

    def for_chain(self, chain: AttackChain) -> list[Mitigation]:
        mitigations: list[Mitigation] = []
        evidence_ids = chain.all_evidence_event_ids() or list(chain.event_ids)
        techniques = [stage.technique for stage in chain.stages if stage.technique]
        ports = ", ".join(str(port) for port in chain.victim_ports[:5]) or "the targeted ports"
        rules = ", ".join(sorted(set(chain.evidence_validation.get("rules") or []))[:3]) or ""
        cves = self._cves(chain)

        for technique in dict.fromkeys(techniques):
            template = TECHNIQUE_MITIGATIONS.get(technique)
            if template is None:
                continue
            mitigations.append(
                Mitigation(
                    mitigation_id=_mitigation_id(chain.chain_id, technique),
                    title=template.title,
                    description=template.description.format(
                        rules=rules or "detected behaviour",
                        ports=ports,
                        cves=f" ({', '.join(cves)})" if cves else "",
                    ),
                    recommendation_type=(
                        MitigationKind.EVIDENCE_BASED
                        if evidence_ids
                        else template.kind
                    ),
                    priority=template.priority,
                    related_techniques=[technique],
                    related_entities=list(chain.victim_ips[:5]),
                    evidence_event_ids=evidence_ids[:10],
                    evidence_chain_ids=[chain.chain_id],
                )
            )
            if len(mitigations) >= MAX_MITIGATIONS_PER_CHAIN:
                break

        for cve in cves[:2]:
            mitigations.append(
                Mitigation(
                    mitigation_id=_mitigation_id(chain.chain_id, cve.lower()),
                    title=f"Remediate {cve}",
                    description=(
                        f"The evidence references {cve}. Identify the affected component "
                        "on the target asset, apply the vendor patch and verify the fix "
                        "with a targeted scan."
                    ),
                    recommendation_type=MitigationKind.EVIDENCE_BASED,
                    priority="high",
                    related_techniques=techniques[:3],
                    related_entities=list(chain.victim_ips[:5]),
                    evidence_event_ids=evidence_ids[:10],
                    evidence_chain_ids=[chain.chain_id],
                )
            )

        if self._has_malicious_indicator(chain):
            mitigations.append(
                Mitigation(
                    mitigation_id=_mitigation_id(chain.chain_id, "block-ioc"),
                    title="Block the identified malicious infrastructure",
                    description=(
                        "Threat intelligence marked an indicator of this chain as "
                        "malicious. Block it at the perimeter, hunt for historical "
                        "connections and review any host that contacted it."
                    ),
                    recommendation_type=MitigationKind.EVIDENCE_BASED,
                    priority="high",
                    related_techniques=techniques[:3],
                    related_entities=list(chain.attacker_ips[:5]),
                    evidence_event_ids=evidence_ids[:10],
                    evidence_chain_ids=[chain.chain_id],
                )
            )
        return mitigations

    def for_chains(self, chains: list[AttackChain]) -> list[Mitigation]:
        collected: dict[str, Mitigation] = {}
        for chain in chains:
            for mitigation in self.for_chain(chain):
                existing = collected.get(mitigation.title)
                if existing is None:
                    collected[mitigation.title] = mitigation
                    continue
                collected[mitigation.title] = existing.model_copy(
                    update={
                        "related_techniques": sorted(
                            set(existing.related_techniques) | set(mitigation.related_techniques)
                        ),
                        "related_entities": sorted(
                            set(existing.related_entities) | set(mitigation.related_entities)
                        ),
                        "evidence_event_ids": sorted(
                            set(existing.evidence_event_ids) | set(mitigation.evidence_event_ids)
                        )[:20],
                        "evidence_chain_ids": sorted(
                            set(existing.evidence_chain_ids) | set(mitigation.evidence_chain_ids)
                        ),
                    }
                )
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(
            collected.values(),
            key=lambda mitigation: (order.get(mitigation.priority, 4), mitigation.title),
        )

    @staticmethod
    def _cves(chain: AttackChain) -> list[str]:
        parts: list[str] = [chain.summary]
        parts.extend(stage.narrative for stage in chain.stages)
        rules = chain.evidence_validation.get("rules")
        if isinstance(rules, list):
            parts.extend(str(rule) for rule in rules)
        # Rule names often use underscores (``cve_2021_44228``); normalise them so
        # the CVE regex also recognises that spelling.
        return extract_cves(" ".join(parts).replace("_", "-"))

    @staticmethod
    def _has_malicious_indicator(chain: AttackChain) -> bool:
        value = chain.evidence_validation.get("malicious_ioc_hits") or 0
        try:
            return int(value) > 0
        except (TypeError, ValueError):
            return False


def _mitigation_id(chain_id: str, suffix: str) -> str:
    digest = hashlib.sha256(f"{chain_id}|{suffix}".encode()).hexdigest()
    return f"mit_{digest[:12]}"
