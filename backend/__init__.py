"""Backend packages of the Network Attack Analysis System.

Layout contract:

* ``backend.common``      - shared, versioned data contracts (public schemas).
* ``backend.module1_*``   - upstream producer (not part of this workstream).
* ``backend.module2_chain`` - attack correlation & intelligent judgement engine.

Modules exchange data **only** through the shared workspace and the versioned
contracts defined in :mod:`backend.common.schemas`.  No module may call another
module over the network.
"""

__all__ = ["common"]
