from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from provenance.http import ReplayHttpClient, SnapshottingHttpClient
from provenance.models import BuildManifest
from provenance.store import SnapshotStore
from utils.http import SourceFetchError, SourceResponse


class FakeTransport:
    def fetch(self, url: str, params=None) -> SourceResponse:
        request_url = (
            f"{url}?format=json&standard=CWE&standard=WSTG"
            if params
            else url
        )
        return SourceResponse(
            request_url=request_url,
            resolved_url=request_url,
            status_code=200,
            headers={},
            content=b'{"result": {}}',
            encoding="utf-8",
        )

    def close(self) -> None:
        return None


def test_replay_uses_snapshot_without_transport(
    tmp_path: Path,
) -> None:
    store = SnapshotStore(tmp_path)
    live = SnapshottingHttpClient(
        store,
        FakeTransport(),
        clock=lambda: datetime(2026, 8, 12, tzinfo=timezone.utc),
    )
    params = {"standard": ["CWE", "WSTG"], "format": "json"}
    assert live.get_json("https://source.test/map", params=params) == {
        "result": {}
    }

    replay = ReplayHttpClient(store, live.manifest())
    assert replay.get_json(
        "https://source.test/map", params=params
    ) == {"result": {}}


def test_replay_fails_for_unlisted_url(tmp_path: Path) -> None:
    replay = ReplayHttpClient(
        SnapshotStore(tmp_path),
        BuildManifest(sources=[]),
    )
    with pytest.raises(SourceFetchError, match="not present in source manifest"):
        replay.get_text("https://source.test/missing")


def test_replay_fails_when_object_digest_is_corrupt(
    tmp_path: Path,
) -> None:
    store = SnapshotStore(tmp_path)
    live = SnapshottingHttpClient(
        store,
        FakeTransport(),
        clock=lambda: datetime(2026, 8, 12, tzinfo=timezone.utc),
    )
    live.get_text("https://source.test/a")
    manifest = live.manifest()
    object_path = (
        tmp_path
        / "objects"
        / manifest.sources[0].sha256.removeprefix("sha256:")
    )
    object_path.write_bytes(b"corrupt")

    replay = ReplayHttpClient(store, manifest)
    with pytest.raises(SourceFetchError, match="digest mismatch"):
        replay.get_text("https://source.test/a")


def test_live_and_replay_decode_non_utf8_bytes_identically(
    tmp_path: Path,
) -> None:
    class LegacyTransport(FakeTransport):
        def fetch(self, url: str, params=None) -> SourceResponse:
            return SourceResponse(
                request_url=url,
                resolved_url=url,
                status_code=200,
                headers={},
                content=b"payload=\x93marker\x94",
                encoding="windows-1252",
            )

    store = SnapshotStore(tmp_path)
    live = SnapshottingHttpClient(store, LegacyTransport())
    live_text = live.get_text("https://source.test/legacy")
    replay_text = ReplayHttpClient(
        store,
        live.manifest(),
    ).get_text("https://source.test/legacy")

    assert live_text == "payload=“marker”"
    assert replay_text == live_text


def test_manifest_rejects_replay_graph_drift() -> None:
    manifest = BuildManifest(
        sources=[],
        stageSummaries={"stage": {"count": 1}},
        graphCounts={"nodes": {"Weakness": 1}},
        graphDigest=f"sha256:{'a' * 64}",
    )
    with pytest.raises(ValueError, match="graph counts differ"):
        manifest.validate_build_result(
            {
                "stages": {"stage": {"count": 1}},
                "graph": {"nodes": {"Weakness": 2}},
                "graphDigest": f"sha256:{'a' * 64}",
            }
        )


def test_manifest_rejects_replay_stage_drift() -> None:
    manifest = BuildManifest(
        sources=[],
        stageSummaries={"stage": {"count": 1}},
        graphCounts={"nodes": {"Weakness": 1}},
        graphDigest=f"sha256:{'a' * 64}",
    )
    with pytest.raises(ValueError, match="stage summaries differ"):
        manifest.validate_build_result(
            {
                "stages": {"stage": {"count": 2}},
                "graph": {"nodes": {"Weakness": 1}},
                "graphDigest": f"sha256:{'a' * 64}",
            }
        )


def test_manifest_rejects_semantic_graph_drift_with_same_counts() -> None:
    manifest = BuildManifest(
        sources=[],
        stageSummaries={"stage": {"count": 1}},
        graphCounts={"nodes": {"Weakness": 1}},
        graphDigest=f"sha256:{'a' * 64}",
    )
    with pytest.raises(ValueError, match="graph digest differs"):
        manifest.validate_build_result(
            {
                "stages": {"stage": {"count": 1}},
                "graph": {"nodes": {"Weakness": 1}},
                "graphDigest": f"sha256:{'b' * 64}",
            }
        )
