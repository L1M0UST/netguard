"""Shared-workspace protocol constants.

Module 1 -> Module 2 (``04_m2_inbox``)::

    task_xxx/
        batch_000001.parquet
        batch_000002.parquet
        manifest.json
        READY              # created last, after fsync + sha256 + rename

Module 2 -> Module 3 (``05_m2_output``)::

    task_xxx/
        alerts/ alerts.json
        chains/ chains.json
        attackers/ attackers.json
        entities/ entities.json
        reports/ report.json
        metrics.json
        manifest.json
        DONE               # created last

Module 2 status (``06_status/m2``)::

    task_xxx.json
"""

DEFAULT_INBOX_SUBDIR = "04_m2_inbox"
DEFAULT_OUTPUT_SUBDIR = "05_m2_output"
DEFAULT_STATUS_SUBDIR = "06_status/m2"

READY_MARKER = "READY"
PROCESSING_MARKER = "PROCESSING"
DONE_MARKER = "DONE"
FAILED_MARKER = "FAILED"
TEMP_SUFFIX = ".tmp"

MANIFEST_FILE = "manifest.json"

#: Directory names inside a Module 2 output bundle.
BUNDLE_DIR_ALERTS = "alerts"
BUNDLE_DIR_CHAINS = "chains"
BUNDLE_DIR_ATTACKERS = "attackers"
BUNDLE_DIR_ENTITIES = "entities"
BUNDLE_DIR_REPORTS = "reports"
BUNDLE_DIR_EVIDENCE = "evidence"

#: Machine readable run summary.
METRICS_FILE = "metrics.json"
