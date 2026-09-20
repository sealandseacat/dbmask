"""dbmask: discover and mask sensitive data in any database.

A general-purpose, open-source toolkit that:
  * connects to any SQLAlchemy-supported database,
  * decides whether a column is sensitive using a layered pipeline
    (history -> field overrides -> pattern matching -> optional LLM),
  * remembers past decisions so masking stays consistent over time,
  * and masks/transforms the data via a pluggable ETL engine.
"""

from dbmask.detection.result import Decision, Sensitivity

__all__ = ["Decision", "Sensitivity", "__version__"]
__version__ = "0.1.2"
