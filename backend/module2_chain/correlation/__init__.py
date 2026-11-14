"""Deterministic first-stage correlation (attacker / victim / time / behaviour).

The package has **no eager imports**: :mod:`backend.module2_chain.attack.
candidate_builder` depends on :mod:`backend.module2_chain.correlation.features`,
and the engine depends on the candidate builder, so importing submodules here
would create a cycle.  Import the concrete modules directly::

    from backend.module2_chain.correlation.engine import CorrelationEngine
    from backend.module2_chain.correlation.features import EventFeatures

Public surface:

* :class:`~backend.module2_chain.correlation.engine.CorrelationEngine`
* :class:`~backend.module2_chain.correlation.temporal.TemporalCorrelator`
* :class:`~backend.module2_chain.correlation.entity.EntityCorrelator`
* :class:`~backend.module2_chain.correlation.behavior.BehaviorCorrelator`
* :class:`~backend.module2_chain.correlation.features.EventFeatures`
* :class:`~backend.module2_chain.correlation.union_find.UnionFind`
"""

__all__ = [
    "behavior",
    "engine",
    "entity",
    "features",
    "temporal",
    "union_find",
]
