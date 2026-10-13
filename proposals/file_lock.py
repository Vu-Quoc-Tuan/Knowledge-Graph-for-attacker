"""Small cross-platform advisory file-locking primitives for event logs."""

from __future__ import annotations

import os
import warnings
from typing import Any


def lock_file(
    fd: int,
    *,
    posix_backend: Any,
    windows_backend: Any,
    error_type: type[Exception],
    resource_name: str,
) -> None:
    """Acquire an exclusive lock, refusing an unsafe unlocked append.

    Windows' byte-range locking requires a byte to exist. Event logs use
    newline-delimited JSON, so an empty log is initialized with a blank line;
    parsers already ignore blank lines and concurrent writers are still
    serialized before they read or append.
    """
    if posix_backend is not None:
        posix_backend.flock(fd, posix_backend.LOCK_EX)
        return
    if windows_backend is not None:
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\n")
            os.lseek(fd, 0, os.SEEK_SET)
            windows_backend.locking(fd, windows_backend.LK_LOCK, 1)
            return
        except OSError as exc:
            raise error_type(
                f"cannot acquire Windows event-log lock for {resource_name}"
            ) from exc
    warnings.warn(
        f"no supported file-lock backend for {resource_name}; refusing unlocked append",
        RuntimeWarning,
        stacklevel=2,
    )
    raise error_type(
        f"file locking is unavailable for {resource_name}; refusing unlocked append"
    )


def unlock_file(
    fd: int,
    *,
    posix_backend: Any,
    windows_backend: Any,
) -> None:
    if posix_backend is not None:
        posix_backend.flock(fd, posix_backend.LOCK_UN)
    elif windows_backend is not None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            windows_backend.locking(fd, windows_backend.LK_UNLCK, 1)
        except OSError:
            # The owning operation already completed; close() will release a
            # Windows lock if the explicit unlock cannot be performed.
            pass
