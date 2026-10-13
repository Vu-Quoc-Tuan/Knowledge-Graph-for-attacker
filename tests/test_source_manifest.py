from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from provenance.http import SnapshottingHttpClient
from provenance.store import SnapshotStore
from utils.http import SourceResponse


class FakeTransport:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.calls = 0

    def fetch(self, url: str, params=None) -> SourceResponse:
        self.calls += 1
        return SourceResponse(
            request_url=url,
            resolved_url=url,
            status_code=200,
            headers={"ETag": '"v1"'},
            content=self.body,
            encoding="utf-8",
        )

    def close(self) -> None:
        return None


def test_snapshot_client_records_digest_and_metadata(
    tmp_path: Path,
) -> None:
    transport = FakeTransport(b'{"value": 1}\n')
    client = SnapshottingHttpClient(
        SnapshotStore(tmp_path),
        transport,
        clock=lambda: datetime(2026, 8, 12, tzinfo=timezone.utc),
    )

    assert client.get_json("https://source.test/a") == {"value": 1}
    manifest = client.manifest()
    entry = manifest.sources[0]
    assert entry.requestUrl == "https://source.test/a"
    assert entry.byteLength == len(b'{"value": 1}\n')
    assert entry.etag == '"v1"'
    assert (tmp_path / "objects" / entry.sha256.removeprefix("sha256:")).is_file()


def test_snapshot_store_deduplicates_identical_bodies(
    tmp_path: Path,
) -> None:
    store = SnapshotStore(tmp_path)
    first = store.put(b"same body")
    second = store.put(b"same body")

    assert first == second
    assert len(list((tmp_path / "objects").iterdir())) == 1
