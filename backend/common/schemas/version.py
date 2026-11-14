"""Contract version constants.

Contract rules (see ``docs/shared_workspace_protocol.md``):

* A version is a ``MAJOR.MINOR.PATCH`` string.
* Inside the same MAJOR version fields may only be **added** (never renamed,
  retyped or removed) and every new field must carry a default.
* Breaking changes require a new MAJOR version and a new schema module.
"""

SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION = "1.0.0"
"""``SuspiciousEventBatch.v1`` written by Module 1 into ``04_m2_inbox``."""

ATTACK_CHAIN_SCHEMA_VERSION = "1.0.0"
ALERT_SCHEMA_VERSION = "1.0.0"
ATTACKER_PROFILE_SCHEMA_VERSION = "1.0.0"
THREAT_ENTITY_SCHEMA_VERSION = "1.0.0"
RISK_EVENT_REPORT_SCHEMA_VERSION = "1.0.0"
MODULE2_BUNDLE_MANIFEST_SCHEMA_VERSION = "1.0.0"
TASK_STATUS_SCHEMA_VERSION = "1.0.0"

SUPPORTED_SUSPICIOUS_EVENT_BATCH_VERSIONS: frozenset[str] = frozenset(
    {SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION, "1.0", "1"}
)
"""Accepted spellings of the batch contract version."""

PRODUCER_MODULE1 = "module1"
PRODUCER_MODULE2 = "module2_chain"
