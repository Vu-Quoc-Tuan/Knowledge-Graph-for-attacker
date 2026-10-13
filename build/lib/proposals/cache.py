"""Process-local checkpoints for replayed event-log folds.

The event log remains the source of truth. A checkpoint is only reused while
the file's size and nanosecond mtime are unchanged, so external writers or a
local append invalidate it automatically.
"""

from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Callable, Generic, TypeVar


T = TypeVar("T")


class EventFoldCheckpoint(Generic[T]):
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = Lock()
        self._signature: tuple[bool, int, int] | None = None
        self._value: T | None = None

    def _file_signature(self) -> tuple[bool, int, int]:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return (False, 0, 0)
        return (True, stat.st_size, stat.st_mtime_ns)

    def get(self, loader: Callable[[], T]) -> T:
        signature = self._file_signature()
        if self._value is not None and signature == self._signature:
            return self._value
        with self._lock:
            signature = self._file_signature()
            if self._value is not None and signature == self._signature:
                return self._value
            value = loader()
            self._signature = signature
            self._value = value
            return value

    def invalidate(self) -> None:
        with self._lock:
            self._signature = None
            self._value = None
