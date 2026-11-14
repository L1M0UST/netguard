"""Attack fingerprinting for cross-run / cross-candidate deduplication (M2-F16)."""

from __future__ import annotations

import hashlib

from backend.common.schemas.attack import AttackChain
from backend.module2_chain.app.config import AppConfig

FINGERPRINT_PREFIX = "af_"


class AttackFingerprintBuilder:
    """Builds a stable sha256 fingerprint for an attack chain.

    Components: attackers + victims + primary tactic/technique + time bucket +
    primary ports + malicious IOC hits.  Two chains describing the same attack
    (same actors, same behaviour, same time bucket) collapse onto one fingerprint.
    """

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.bucket_seconds = max(
            60.0, float(config.correlation.correlation_window_seconds)
        )

    def components(self, chain: AttackChain) -> dict[str, str]:
        stages = sorted(chain.stages, key=lambda item: item.stage_index)
        primary = stages[0] if stages else None
        last = stages[-1] if stages else None
        first_seen = chain.first_seen
        bucket = int(first_seen.timestamp() // self.bucket_seconds) if first_seen else 0
        return {
            "attackers": ",".join(sorted(chain.attacker_ips)),
            "victims": ",".join(sorted(chain.victim_ips)),
            "first_tactic": primary.tactic if primary else "",
            "last_tactic": last.tactic if last else "",
            "first_technique": (primary.technique or "") if primary else "",
            "last_technique": (last.technique or "") if last else "",
            "time_bucket": str(bucket),
            "ports": ",".join(str(port) for port in sorted(set(chain.victim_ports))[:8]),
        }

    def fingerprint(self, chain: AttackChain) -> str:
        components = self.components(chain)
        payload = "|".join(f"{key}={value}" for key, value in sorted(components.items()))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"{FINGERPRINT_PREFIX}{digest[:40]}"

    def apply(self, chain: AttackChain) -> AttackChain:
        return chain.model_copy(update={"fingerprint": self.fingerprint(chain)})
