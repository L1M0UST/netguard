"""Module 2 - Attack Correlation & Intelligent Judgement Engine.

Module 2 is a *standalone data-processing application*.  It never exposes a
network API and never calls Module 1 / Module 3 over the network.  The only
integration surface is the shared workspace:

``04_m2_inbox``  ->  (read, READY/PROCESSING/DONE)  ->  ``05_m2_output``

See ``docs/module2_overview.md`` for the full design.
"""

__version__ = "1.0.0"
