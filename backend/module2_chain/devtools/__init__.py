"""Developer utilities: synthetic data generation and self tests.

These helpers exist so Module 2 can be exercised **without** Module 1 (spec §53)
and so the fixture generator and the ``selftest`` CLI can share one source of
truth.
"""

from backend.module2_chain.devtools.synthetic import (
    SCENARIOS,
    build_batch,
    build_events,
    build_mixed_batch,
    write_batch,
)

__all__ = [
    "SCENARIOS",
    "build_batch",
    "build_events",
    "build_mixed_batch",
    "write_batch",
]
