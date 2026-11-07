"""PostgreSQL masking progress committed in the same transaction as the data."""
from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace

from sqlalchemy import Column, MetaData, String, Table, func, inspect, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Connection
from sqlalchemy.schema import CreateSchema

from dbmask.connectors.sql import SQLConnector

CHECKPOINT_SCHEMA = "dbmask_internal"
_RUNS = Table(
    "mask_runs_v1", MetaData(),
    Column("run_id", String(36), primary_key=True),
    Column("plan_sha256", String(64), nullable=False),
    Column("tables", JSONB, nullable=False),
    schema=CHECKPOINT_SCHEMA,
)
_LOCK_KEY = int.from_bytes(b"DBMASK", "big")


@dataclass(frozen=True)
class TableCheckpoint:
    schema: str
    table: str
    total_rows: int
    rows_written: int = 0
    committed_batches: int = 0


class PostgresCheckpoint:
    """A resumable apply on a stable, exclusively operated target copy.

    Keep the PostgreSQL session that owns the advisory lock through each
    write transaction. Page reads use the connector's short-lived reads.
    The journal stores counts, never primary-key values or masked payloads.
    """

    def __init__(self, connector: SQLConnector, connection: Connection, run_id: str,
                 tables: dict[tuple[str, str], TableCheckpoint]):
        self.connector = connector
        self.connection = connection
        self.run_id = run_id
        self.tables = tables

    @classmethod
    @contextmanager
    def open(
        cls, connector: SQLConnector, run_id: str, plan_sha256: str,
        table_names: Iterable[tuple[str, str]], *, resume: bool,
    ) -> Iterator[PostgresCheckpoint]:
        engine = connector.engine
        if engine is None or engine.dialect.name != "postgresql":
            raise ValueError("Resumable masking requires a PostgreSQL target")
        if not connector.cfg.schemas or CHECKPOINT_SCHEMA in connector.cfg.schemas:
            raise ValueError(f"Resumable masking requires explicit database.schemas excluding {CHECKPOINT_SCHEMA}")

        with engine.connect() as connection:
            # Close the physical session, including its lock, on every exit.
            connection.detach()
            with connection.begin():
                if not connection.scalar(select(func.pg_try_advisory_lock(_LOCK_KEY))):
                    raise ValueError("Another resumable masking process holds the PostgreSQL target lock")
                inspector = inspect(connection)
                if not inspector.has_table(_RUNS.name, schema=CHECKPOINT_SCHEMA):
                    if resume:
                        raise ValueError("No PostgreSQL checkpoint found for this run; resume requires a prior --resumable apply")
                    if not inspector.has_schema(CHECKPOINT_SCHEMA):
                        connection.execute(CreateSchema(CHECKPOINT_SCHEMA, if_not_exists=True))
                    _RUNS.create(connection)
                saved = connection.execute(
                    select(_RUNS.c.plan_sha256, _RUNS.c.tables).where(_RUNS.c.run_id == run_id)
                ).one_or_none()
                if resume and saved is None:
                    raise ValueError("No PostgreSQL checkpoint found for this run; resume requires a prior --resumable apply")
                if not resume and saved is not None:
                    raise ValueError("This run already has a PostgreSQL checkpoint; use --resume")

                totals = {(s, t): connector.row_count(s, t) for s, t in table_names}
                if saved is None:
                    tables = {key: TableCheckpoint(*key, count) for key, count in totals.items()}
                    connection.execute(_RUNS.insert().values(
                        run_id=run_id, plan_sha256=plan_sha256,
                        tables=[asdict(state) for state in tables.values()],
                    ))
                else:
                    if saved.plan_sha256 != plan_sha256:
                        raise ValueError("PostgreSQL checkpoint does not match the approved plan")
                    tables = cls._read_tables(saved.tables, totals)
            yield cls(connector, connection, run_id, tables)

    @staticmethod
    def _read_tables(payload: list[dict], totals: dict[tuple[str, str], int]) -> dict[tuple[str, str], TableCheckpoint]:
        try:
            entries = [TableCheckpoint(**item) for item in payload]
            tables = {(item.schema, item.table): item for item in entries}
        except TypeError as exc:
            raise ValueError("Invalid PostgreSQL masking checkpoint") from exc
        if len(tables) != len(entries) or tables.keys() != totals.keys():
            raise ValueError("PostgreSQL checkpoint does not match the planned tables")
        for key, item in tables.items():
            counts = (item.total_rows, item.rows_written, item.committed_batches)
            if (any(type(count) is not int or count < 0 for count in counts)
                    or not item.committed_batches <= item.rows_written <= item.total_rows
                    or bool(item.committed_batches) != bool(item.rows_written)):
                raise ValueError("Invalid row or batch counts in PostgreSQL checkpoint")
            if item.total_rows != totals[key]:
                raise ValueError(f"Target row count changed for {item.schema}.{item.table}; cannot resume")
        return tables

    def iter_pages(self, schema: str, table: str, keys: list[str], batch_size: int) -> Iterable[list[dict]]:
        state = self.tables[(schema, table)]
        if state.rows_written == state.total_rows:
            return ()
        return self.connector.iter_pages(
            schema, table, key_columns=keys, batch_size=batch_size, skip_rows=state.rows_written,
        )

    def update_rows(self, schema: str, table: str, key_columns: list[str], rows: list[dict]) -> int:
        key = (schema, table)
        state = self.tables[key]
        next_state = replace(state, rows_written=state.rows_written + len(rows),
                             committed_batches=state.committed_batches + 1)
        if next_state.rows_written > state.total_rows:
            raise ValueError(f"Target row count changed for {schema}.{table} during masking")
        tables = {**self.tables, key: next_state}
        with self.connection.begin():
            affected = self.connector.update_rows(schema, table, key_columns, rows, connection=self.connection)
            if affected != len(rows):
                raise ValueError(f"Unexpected number of rows updated for {schema}.{table}; batch rolled back")
            updated = self.connection.execute(
                _RUNS.update().where(_RUNS.c.run_id == self.run_id)
                .values(tables=[asdict(item) for item in tables.values()])
            )
            if updated.rowcount != 1:
                raise ValueError("PostgreSQL checkpoint disappeared; batch rolled back")
        self.tables = tables
        return affected

    def require_complete(self) -> None:
        for item in self.tables.values():
            if item.rows_written != item.total_rows:
                raise ValueError(f"Target row count changed for {item.schema}.{item.table} during masking")
