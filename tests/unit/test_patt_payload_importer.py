from datetime import datetime, timezone

import pytest

from ckg.application.ingest_patt import ingest_patt_sources
from ckg.graph.memory import InMemoryGraphRepository
from ckg.graph.models import GraphNode
from ckg.ingestion.patt.payload_importer import (
    PATTSourceFile,
    restore_patt_semantic_plane,
)
from ckg.ingestion.patt.payload_index import PATTIndex


NOW = datetime(2026, 9, 22, tzinfo=timezone.utc)


def _repository(cwe_id: str = "CWE-79") -> InMemoryGraphRepository:
    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[GraphNode(label="CWE", node_id=cwe_id, props={})], edges=[])
    return repository


def test_import_keeps_patt_provenance_and_untested_state(tmp_path) -> None:
    repository = _repository()

    report = ingest_patt_sources(
        repository,
        slice_cwe_id="CWE-79",
        sources=(PATTSourceFile(
            "README.md", "https://example.test/xss", "a" * 40,
            "## XSS\n```html\n<img src=x onerror=alert(1)>\n```",
            technology="PHP",
        ),),
        retrieved_at=NOW,
        snapshot_root=tmp_path / "snapshots",
    )

    payload = PATTIndex(tmp_path / "snapshots" / "patt_payloads.sqlite3").query()["payloads"][0]
    assert report.payload_count == 1
    assert payload["origin"] == "patt"
    assert payload["curation_status"] == "upstream_curated"
    assert payload["validation_status"] == "untested"
    assert payload["source_snapshot_digest"].startswith("sha256:")
    assert repository.nodes("Payload") == []
    assert repository.nodes("PATTSection") == []
    assert len(repository.nodes("PATTDocument")) == 1
    assert len(repository.nodes("Evidence")) == 1
    assert repository.edges("HAS_PAYLOAD_FAMILY")[0].subject_id == "CWE-79"
    assert repository.nodes("PayloadFamily")[0].props["technologies"] == ["PHP"]
    assert not [edge for edge in repository.edges() if edge.subject_id.startswith(("CVE-", "GHSA-"))]
    assert repository.nodes("Scenario") == []


def test_imports_intruder_wordlist_as_reference_only(tmp_path) -> None:
    repository = _repository()

    report = ingest_patt_sources(
        repository,
        slice_cwe_id="CWE-79",
        sources=(PATTSourceFile(
            "xss.txt", "https://example.test/xss.txt", "b" * 40,
            "# comment\n\n<svg/onload=alert(1)>\n<img src=x onerror=1>",
            kind="wordlist",
        ),),
        retrieved_at=NOW,
        snapshot_root=tmp_path / "snapshots",
    )

    payloads = PATTIndex(tmp_path / "snapshots" / "patt_payloads.sqlite3").query()["payloads"]
    assert report.payload_count == 2
    assert {payload["locator"] for payload in payloads} == {"/lines/3", "/lines/4"}
    assert {payload["extraction"] for payload in payloads} == {"intruder_wordlist"}
    assert all(payload["validation_status"] == "untested" for payload in payloads)
    assert repository.nodes("Payload") == []


def test_import_is_idempotent_and_honors_family_cap(tmp_path) -> None:
    repository = _repository()
    source = PATTSourceFile(
        "README.md", "https://example.test/xss", "c" * 40,
        "## XSS\n```html\n<img src=x onerror=1>\n<svg/onload=1>\n```",
    )

    first = ingest_patt_sources(
        repository, slice_cwe_id="CWE-79", sources=(source,), retrieved_at=NOW,
        snapshot_root=tmp_path / "snapshots", max_payloads_per_family=1,
    )
    second = ingest_patt_sources(
        repository, slice_cwe_id="CWE-79", sources=(source,), retrieved_at=NOW,
        snapshot_root=tmp_path / "snapshots", max_payloads_per_family=1,
    )

    assert first.payload_count == second.payload_count == 1
    assert first.skipped_over_cap == second.skipped_over_cap == 1
    assert len(repository.nodes("Payload")) == 0
    assert PATTIndex(tmp_path / "snapshots" / "patt_payloads.sqlite3").query()["total"] == 1


def test_reimport_unions_family_technology_context_instead_of_overwriting(tmp_path) -> None:
    repository = _repository()
    snapshots = tmp_path / "snapshots"
    for filename, revision, technology, payload in (
        ("php.md", "e" * 40, "PHP", "<img src=x onerror=1>"),
        ("js.md", "f" * 40, "JavaScript", "<svg/onload=1>"),
    ):
        ingest_patt_sources(
            repository,
            slice_cwe_id="CWE-79",
            sources=(PATTSourceFile(
                filename, f"https://example.test/{filename}", revision,
                f"## XSS\n```html\n{payload}\n```", technology=technology,
            ),),
            retrieved_at=NOW,
            snapshot_root=snapshots,
        )

    family = repository.nodes("PayloadFamily")[0]
    assert family.props["technologies"] == ["JavaScript", "PHP"]


def test_rejects_unknown_cwe_and_unsupported_wordlist(tmp_path) -> None:
    with pytest.raises(ValueError, match="unknown PATT slice"):
        ingest_patt_sources(
            _repository("CWE-999"), slice_cwe_id="CWE-999", sources=(),
            retrieved_at=NOW, snapshot_root=tmp_path / "snapshots",
        )
    with pytest.raises(ValueError, match="no Intruder family"):
        ingest_patt_sources(
            _repository("CWE-918"), slice_cwe_id="CWE-918",
            sources=(PATTSourceFile("ssrf.txt", "https://example.test/ssrf.txt", "d" * 40, "http://127.0.0.1", kind="wordlist"),),
            retrieved_at=NOW, snapshot_root=tmp_path / "snapshots",
        )


def test_cached_payload_index_restores_compact_family_and_technology_plane(tmp_path) -> None:
    repository = _repository()
    index = PATTIndex(tmp_path / "patt_payloads.sqlite3")
    index.put_many([
        {
            "payload_id": "payload-1", "cwe_id": "CWE-79",
            "family_key": "xss.generic", "family_name": "Cross-site scripting",
            "technology": "PHP", "value": "<svg/onload=1>",
            "source_file": "XSS/README.md", "source_url": "https://example.test/xss",
            "source_revision": "a" * 40, "source_kind": "markdown",
            "source_snapshot_digest": "sha256:" + "1" * 64,
            "locator": "heading:XSS", "extraction": "fenced_code",
        },
        {
            "payload_id": "payload-2", "cwe_id": "CWE-79",
            "family_key": "xss.generic", "family_name": "Cross-site scripting",
            "technology": "JavaScript", "value": "<img src=x onerror=1>",
            "source_file": "XSS/README.md", "source_url": "https://example.test/xss",
            "source_revision": "a" * 40, "source_kind": "markdown",
            "source_snapshot_digest": "sha256:" + "2" * 64,
            "locator": "heading:XSS", "extraction": "fenced_code",
        },
    ])

    report = restore_patt_semantic_plane(
        repository,
        payload_index=index,
        cwe_ids=frozenset({"CWE-79"}),
    )

    family = repository.nodes("PayloadFamily")
    technologies = repository.nodes("Technology")
    assert report.cwe_count == 1
    assert report.payload_count == 2
    assert report.family_count == 1
    assert report.technology_count == 2
    assert len(family) == 1
    assert family[0].props["detection_signal"] == "script_execution"
    assert family[0].props["payload_count"] == 2
    assert family[0].props["source_revisions"] == ["a" * 40]
    assert family[0].props["source_snapshot_digests"] == [
        "sha256:" + "1" * 64,
        "sha256:" + "2" * 64,
    ]
    assert {node.props["name"] for node in technologies} == {"PHP", "JavaScript"}
    assert len(repository.edges("HAS_PAYLOAD_FAMILY")) == 1
    assert len(repository.edges("APPLIES_TO")) == 2
    assert repository.nodes("Payload") == []


def test_family_inventory_does_not_return_raw_payload_text(tmp_path) -> None:
    index = PATTIndex(tmp_path / "patt_payloads.sqlite3")
    index.put_many([{
        "payload_id": "payload-1", "cwe_id": "CWE-79",
        "family_key": "xss.generic", "family_name": "Cross-site scripting",
        "technology": "PHP", "value": "<script>secret-marker</script>",
        "source_file": "XSS/README.md", "source_url": "https://example.test/xss",
        "source_revision": "a" * 40, "source_kind": "markdown",
        "source_snapshot_digest": "sha256:" + "1" * 64,
        "locator": "heading:XSS", "extraction": "fenced_code",
    }])

    inventory = index.family_inventory(cwe_ids=("CWE-79",))

    assert inventory == ({
        "cwe_id": "CWE-79",
        "family_key": "xss.generic",
        "family_name": "Cross-site scripting",
        "payload_count": 1,
        "technologies": ["PHP"],
        "source_revisions": ["a" * 40],
        "source_snapshot_digests": ["sha256:" + "1" * 64],
    },)
    assert "secret-marker" not in repr(inventory)


def test_cached_semantic_restore_fails_closed_when_native_slice_is_missing(tmp_path) -> None:
    repository = _repository()
    index = PATTIndex(tmp_path / "empty-patt-index.sqlite3")

    with pytest.raises(ValueError, match="no source-backed family records"):
        restore_patt_semantic_plane(
            repository,
            payload_index=index,
            cwe_ids=frozenset({"CWE-79"}),
        )

    assert repository.nodes("PayloadFamily") == []
    assert repository.nodes("Technology") == []
