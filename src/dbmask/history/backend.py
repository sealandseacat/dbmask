"""Choose one authoritative history source; never maintain two writable copies."""
from __future__ import annotations

from typing import Union

from dbmask.config import HistoryConfig
from dbmask.history.file_store import FileHistoryStore
from dbmask.history.store import HistoryStore

HistoryBackend = Union[HistoryStore, FileHistoryStore]


def history_backend(config: HistoryConfig) -> HistoryBackend:
    if config.source_file:
        return FileHistoryStore(config.source_file, sheet=config.sheet)
    return HistoryStore(config.url)
