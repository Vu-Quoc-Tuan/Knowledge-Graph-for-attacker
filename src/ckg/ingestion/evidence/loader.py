"""One safe, snapshot-first raw URL loader shared by evidence source kinds."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import requests

try:
    from ckg.provenance.store import SnapshotStore
except ImportError:
    from provenance.store import SnapshotStore


@dataclass(frozen=True)
class LoadedEvidence:
    source_url: str
    content_digest: str
    storage_uri: str
    retrieved_at: datetime
    content_type: str | None


def load_url(url: str, *, snapshot_root: str | Path, timeout: float = 30.0) -> LoadedEvidence:
    """Fetch bytes and store them unchanged; callers choose any later parsing."""
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    store = SnapshotStore(snapshot_root)
    digest = store.put(response.content)
    return LoadedEvidence(
        source_url=url,
        content_digest=digest,
        storage_uri=str(store.objects / digest.removeprefix("sha256:")),
        retrieved_at=datetime.now(timezone.utc),
        content_type=response.headers.get("content-type"),
    )
