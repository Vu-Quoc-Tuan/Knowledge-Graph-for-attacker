from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path


class SnapshotStoreError(ValueError):
    """A source snapshot object is missing or corrupt."""


class SnapshotStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects"

    @staticmethod
    def _digest(content: bytes) -> str:
        return f"sha256:{hashlib.sha256(content).hexdigest()}"

    @staticmethod
    def _object_name(digest: str) -> str:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise SnapshotStoreError(f"invalid snapshot digest {digest!r}")
        return digest.removeprefix("sha256:")

    def put(self, content: bytes) -> str:
        digest = self._digest(content)
        destination = self.objects / self._object_name(digest)
        self.objects.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            existing = destination.read_bytes()
            if self._digest(existing) != digest:
                raise SnapshotStoreError(
                    f"snapshot object {destination} has a digest mismatch"
                )
            return digest

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            dir=self.objects,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, destination)
            temporary_name = ""
        finally:
            if temporary_name:
                Path(temporary_name).unlink(missing_ok=True)
        return digest

    def read(self, digest: str) -> bytes:
        path = self.objects / self._object_name(digest)
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise SnapshotStoreError(
                f"snapshot object for {digest} does not exist"
            ) from exc
        actual = self._digest(content)
        if actual != digest:
            raise SnapshotStoreError(
                f"snapshot object {path} has a digest mismatch: "
                f"expected {digest}, got {actual}"
            )
        return content
