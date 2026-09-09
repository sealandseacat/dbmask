"""Abstract connector interface.

The default implementation (:class:`dbmask.connectors.sql.SQLConnector`) covers
every database SQLAlchemy supports. The interface is kept small so anyone can
plug in an exotic data source (a REST API, a CSV lake, MongoDB, ...) by
subclassing :class:`Connector`.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ColumnRef:
    """A fully-qualified column location."""

    schema: str
    table: str
    column: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.schema}.{self.table}.{self.column}"


class Connector(ABC):
    """Minimal surface every data source must implement."""

    #: Logical database name used in reports/history.
    name: str

    @abstractmethod
    def connect(self) -> None:
        """Open the underlying connection/engine."""

    @abstractmethod
    def close(self) -> None:
        """Release resources."""

    @abstractmethod
    def list_schemas(self) -> list[str]:
        """Return the names of the schemas available in this database."""

    @abstractmethod
    def list_tables(self, schema: str) -> list[str]:
        """Return the table names in ``schema``."""

    @abstractmethod
    def list_columns(self, schema: str, table: str) -> list[str]:
        """Return the column names of ``schema.table``."""

    def column_type(self, schema: str, table: str, column: str) -> Optional[str]:
        """Return the declared type for history drift checks, or None if unavailable."""
        return None

    @abstractmethod
    def sample_values(
        self, schema: str, table: str, column: str, limit: int = 100
    ) -> list[str]:
        """Return up to ``limit`` distinct, non-null sample values as strings."""

    @abstractmethod
    def iter_rows(
        self, schema: str, table: str, columns: Optional[list[str]] = None, batch_size: int = 1000
    ) -> Iterable[dict]:
        """Yield rows (as dicts) for masking. Used by the ETL engine."""

    @abstractmethod
    def update_rows(
        self, schema: str, table: str, key_columns: list[str], rows: list[dict]
    ) -> int:
        """Write masked rows back. Returns number of affected rows."""

    def iter_pages(
        self,
        schema: str,
        table: str,
        key_columns: list[str],
        columns: Optional[list[str]] = None,
        batch_size: int = 1000,
    ) -> Iterable[list[dict]]:
        """Yield rows in pages (lists of dicts) for read-then-write ETL.

        The masking engine writes each page back to the *same table* before
        asking for the next one, so implementations for transactional stores
        must not keep a read transaction or live cursor open across the
        ``yield`` — on SQLite, for example, an open reader blocks the writer's
        commit and the run dies with "database is locked". See
        :meth:`dbmask.connectors.sql.SQLConnector.iter_pages` for the
        reference implementation (keyset pagination, one short-lived
        connection per page).

        This default simply chunks :meth:`iter_rows` and is only suitable for
        connectors whose reads cannot block their writes (REST APIs, files,
        ...).
        """
        page: list[dict] = []
        for row in self.iter_rows(schema, table, columns=columns, batch_size=batch_size):
            page.append(row)
            if len(page) >= batch_size:
                yield page
                page = []
        if page:
            yield page

    @abstractmethod
    def primary_key_columns(self, schema: str, table: str) -> list[str]:
        """Return the primary-key column names of ``schema.table``, empty if none."""

    # -- validation support (optional; default implementations raise) ---------
    # These power the `validate` command. SQLConnector implements them; custom
    # connectors can override as needed.
    def row_count(self, schema: str, table: str) -> int:
        raise NotImplementedError

    def distinct_values(
        self, schema: str, table: str, column: str, limit: int = 5000
    ) -> list:
        """Return up to ``limit`` distinct non-null values (native types)."""
        raise NotImplementedError

    def fetch_rows_where(
        self,
        schema: str,
        table: str,
        columns: list[str],
        where_column: str,
        where_value,
        limit: int = 50,
    ) -> list[tuple]:
        """Return rows (as tuples over ``columns``) where ``where_column`` equals
        ``where_value``. Used by the row-based masking-completeness check."""
        raise NotImplementedError

    def schema_elements(self, schema: str, table: str) -> dict:
        """Return a dict describing a table's structure (columns, pk, indexes,
        foreign keys, unique/check constraints) for source/target comparison."""
        raise NotImplementedError

    # -- context manager sugar ------------------------------------------------
    def __enter__(self) -> Connector:
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
