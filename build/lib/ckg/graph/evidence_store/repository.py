from __future__ import annotations

import hashlib
from pathlib import Path


class FileEvidenceStore:
    """Stores raw source bytes by SHA-256 without rewriting an existing object."""

    def __init__(self, root: str | Path) -> None:
        self._objects = Path(root) / "objects"

    def put(self, content: bytes) -> str:
        digest = hashlib.sha256(content).hexdigest()
        destination = self._objects / digest
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.read_bytes() != content:
                raise ValueError(f"content-addressed collision for {digest}")
            return f"sha256:{digest}"
        temporary = destination.with_name(f".{digest}.tmp")
        try:
            temporary.write_bytes(content)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
        return f"sha256:{digest}"

    def get(self, digest: str) -> bytes:
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError("evidence digest must be sha256:<64 hex characters>")
        content = (self._objects / digest.removeprefix("sha256:")).read_bytes()
        actual = f"sha256:{hashlib.sha256(content).hexdigest()}"
        if actual != digest:
            raise ValueError(f"evidence object digest mismatch: {digest}")
        return content
