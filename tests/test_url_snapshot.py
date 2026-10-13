from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from ai_producers.provider import AISettings
from ai_producers.url_ingest import URLWeaknessIngester, store_source_snapshot
from db.sink import DryRunSink
from ingest.local_weakness_loader import (
    LocalRegistryError,
    load_local_weaknesses,
)
from retrieval.queries import weakness_card


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
    )


def _repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Test User")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    return tmp_path


def _write_registry(
    repo: Path,
    snapshot_ref: str,
    digest: str,
) -> Path:
    path = repo / "registry/weaknesses.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "weaknesses": [
                    {
                        "weakness_id": "LAB-2026-001",
                        "namespace": "LAB",
                        "name": "Snapshot-backed weakness",
                        "summary": "An extracted local weakness.",
                        "lifecycle_status": "proposed",
                        "source_type": "advisory",
                        "source_url": "https://example.test/advisory",
                        "source_title": "Example advisory",
                        "source_hash": digest,
                        "source_snapshot": snapshot_ref,
                        "source_excerpt": "authoritative advisory bytes",
                        "declared_by": "Example publisher",
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


def test_source_snapshot_is_content_addressed_and_idempotent(
    tmp_path: Path,
) -> None:
    raw = b"<html><title>Advisory</title></html>\n"
    first_ref, first_hash = store_source_snapshot(
        tmp_path,
        raw,
        ".html",
    )
    second_ref, second_hash = store_source_snapshot(
        tmp_path,
        raw,
        ".html",
    )

    assert first_ref == second_ref
    assert first_hash == second_hash
    assert (tmp_path / first_ref).read_bytes() == raw


def test_local_weakness_loader_verifies_committed_snapshot(
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    snapshot_ref, digest = store_source_snapshot(
        repo,
        b"authoritative advisory bytes\n",
        ".txt",
    )
    registry = _write_registry(repo, snapshot_ref, digest)
    _git(repo, "add", "registry")
    _git(repo, "commit", "-qm", "add source snapshot")

    sink = DryRunSink()
    load_local_weaknesses(sink, registry)
    node = sink.get_node("Weakness", "weaknessId", "LAB-2026-001")
    assert node is not None
    assert node["sourceSnapshot"] == snapshot_ref
    assert node["sourceHash"] == digest
    assert node["sourceExcerpt"] == "authoritative advisory bytes"
    card = weakness_card(sink, "LAB-2026-001")
    assert card is not None
    assert card["provenance"]["sourceSnapshot"] == snapshot_ref
    assert card["provenance"]["sourceHash"] == digest


def test_local_weakness_loader_rejects_snapshot_hash_mismatch(
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    snapshot_ref, _digest = store_source_snapshot(
        repo,
        b"authoritative advisory bytes\n",
        ".txt",
    )
    registry = _write_registry(
        repo,
        snapshot_ref,
        f"sha256:{'0' * 64}",
    )
    _git(repo, "add", "registry")
    _git(repo, "commit", "-qm", "add invalid source snapshot")

    with pytest.raises(LocalRegistryError, match="source_hash mismatch"):
        load_local_weaknesses(DryRunSink(), registry)


class FakeHttp:
    def get_bytes_and_text(self, url: str) -> tuple[bytes, str]:
        raw = b"<html><title>Advisory</title><p>New weakness</p></html>"
        return raw, raw.decode("utf-8")


class FakeProvider:
    def structured_chat(self, messages, *, schema_name, schema):
        return {
            "name": "New weakness",
            "summary": "A source-grounded local weakness.",
            "technologies": ["Python"],
            "declaredBy": "Example publisher",
            "sourceType": "advisory",
            "suggestedNamespace": "LAB",
        }


def _ai_settings(tmp_path: Path) -> AISettings:
    return AISettings(
        api_url="https://chat.example.invalid/v1",
        api_key="test",
        model_name="fake",
        embedding_model_name="fake-embedding",
        embedding_dimensions=None,
        embedding_batch_size=1,
        candidate_top_k=1,
        max_relation_proposals=1,
        max_payload_proposals=1,
        max_source_chars=1000,
        embedding_cache=str(tmp_path / "cache.sqlite3"),
        timeout=5,
    )


def test_url_preview_is_read_only_and_write_persists_snapshot(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "registry/weaknesses.yaml"
    ingester = URLWeaknessIngester(
        FakeHttp(),  # type: ignore[arg-type]
        FakeProvider(),
        _ai_settings(tmp_path),
        repo_root=tmp_path,
        registry_path=registry,
    )

    entry = ingester.extract_draft("https://example.test/advisory")
    assert entry.source_snapshot is not None
    assert entry.source_excerpt is not None
    assert "Advisory" in entry.source_excerpt
    assert not (tmp_path / entry.source_snapshot).exists()
    assert not registry.exists()

    ingester.append_to_registry(entry, registry)
    assert (tmp_path / entry.source_snapshot).is_file()
    assert registry.is_file()
