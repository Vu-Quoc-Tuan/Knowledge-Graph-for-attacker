import sqlite3

import pytest

from ckg.graph.models import GraphEdge, GraphNode
from ckg.provenance.compact_details import (
    CompactDetailStore,
    collect_compact_detail_records,
    export_compact_details,
)


def _node(label: str, node_id: str, **props: object) -> GraphNode:
    return GraphNode(label=label, node_id=node_id, props=dict(props))


def _edge(edge_id: str, edge_type: str, subject_id: str, object_id: str, **props: object) -> GraphEdge:
    return GraphEdge(
        edge_id=edge_id,
        edge_type=edge_type,
        subject_id=subject_id,
        object_id=object_id,
        props=dict(props),
    )


def test_compact_sidecar_round_trips_nodes_edges_and_provenance(tmp_path) -> None:
    digest = "sha256:" + "a" * 64
    nodes = [
        _node("CAPEC", "CAPEC-100"),
        _node("AttackStep", "CAPEC-100-STEP-1", capec_id="CAPEC-100", ordinal=1, source_snapshot_digest=digest),
        _node("AttackPrerequisite", "CAPEC-100-PREREQ-1", capec_id="CAPEC-100", text="user access"),
        _node("CWECategory", "CWE-CATEGORY-1", name="Injection", source_snapshot_digest=digest),
        _node("CWE", "CWE-89"),
        _node("PATTDocument", "PATT-DOCUMENT-1", slice_cwe_id="CWE-89", source_snapshot_digest=digest),
        _node("Evidence", "EVID-PATT-1", kind="patt_markdown", content_digest=digest),
        _node("Evidence", "EVID-WSTG-1", kind="wstg_markdown", content_digest=digest),
    ]
    edges = [
        _edge("step-edge", "HAS_ATTACK_STEP", "CAPEC-100", "CAPEC-100-STEP-1", ordinal=1),
        _edge("prereq-edge", "HAS_PREREQUISITE", "CAPEC-100", "CAPEC-100-PREREQ-1"),
        _edge("member-edge", "HAS_MEMBER", "CWE-CATEGORY-1", "CWE-89", source_snapshot_digest=digest),
        _edge("patt-edge", "SUPPORTED_BY", "PATT-DOCUMENT-1", "EVID-PATT-1", source_snapshot_digest=digest),
    ]

    store = CompactDetailStore(tmp_path / "compact_details.sqlite3")
    report = export_compact_details(nodes, edges, store)

    assert report.node_count == 5
    assert report.edge_count == 4
    assert report.by_kind == {
        "capec_attack_step": 1,
        "capec_prerequisite": 1,
        "compact_edge": 4,
        "cwe_taxonomy_group": 1,
        "patt_document": 1,
        "patt_evidence": 1,
    }
    step = store.query(detail_kind="capec_attack_step", parent_id="CAPEC-100")
    assert step[0]["payload"]["props"]["ordinal"] == 1
    assert step[0]["source_snapshot_digest"] == digest

    compact_edges = store.query(detail_kind="compact_edge")
    assert {item["payload"]["edge"]["edge_id"] for item in compact_edges} == {
        "step-edge",
        "prereq-edge",
        "member-edge",
        "patt-edge",
    }
    assert store.snapshot_digests() == {digest}
    assert not store.query(detail_kind="patt_evidence", parent_id="EVID-WSTG-1")


def test_compact_collection_is_empty_for_semantic_nodes_only() -> None:
    nodes = [_node("CWE", "CWE-89"), _node("Evidence", "EVID-1", kind="wstg_markdown")]
    assert collect_compact_detail_records(nodes, []) == ()


@pytest.mark.parametrize("catalog", ["CWE", "CAPEC"])
def test_canonical_revision_round_trip(tmp_path, catalog: str) -> None:
    canonical_id = f"{catalog}-79"
    revision = _node(
        f"{catalog}ContentRevision",
        f"{catalog}-CONTENT-79-v1",
        canonical_id=canonical_id,
        retrieved_at="2026-01-01T00:00:00+00:00",
        source_snapshot_digest="sha256:" + "a" * 64,
        description="original definition",
    )
    store = CompactDetailStore(tmp_path / "compact_details.sqlite3")
    report = export_compact_details([revision], [], store)

    assert report.by_kind == {f"{catalog.lower()}_content_revision": 1}
    assert store.query(detail_kind=f"{catalog.lower()}_content_revision")[0]["parent_id"] == canonical_id
    assert store.canonical_revisions(catalog) == [revision]


def test_canonical_revision_reader_rejects_malformed_payload(tmp_path) -> None:
    revision = _node(
        "CWEContentRevision", "REV-1",
        canonical_id="CWE-89", retrieved_at="2026-01-01T00:00:00+00:00",
    )
    store = CompactDetailStore(tmp_path / "compact_details.sqlite3")
    export_compact_details([revision], [], store)
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE compact_details SET payload_json = ? WHERE detail_id = ?", ("{}", "REV-1"))

    with pytest.raises(ValueError, match="invalid CWE content revisions"):
        store.canonical_revisions("CWE")


def test_absent_sidecar_read_does_not_create_a_database(tmp_path) -> None:
    store = CompactDetailStore(tmp_path / "compact_details.sqlite3")
    assert store.canonical_revisions("CWE") == []
    assert not store.path.exists()


def test_second_rebuild_retains_sidecar_only_content_revision(tmp_path) -> None:
    from scripts.rebuild_focused_graph import _merge_rebuild_details

    store = CompactDetailStore(tmp_path / "compact_details.sqlite3")
    revision = _node(
        "CWEContentRevision", "REV-89-OLD",
        canonical_id="CWE-89", retrieved_at="2025-01-01T00:00:00+00:00",
        source_snapshot_digest="sha256:" + "a" * 64,
        description="historical content",
    )
    parent = _node("CWE", "CWE-89")
    relation = _edge("HAS-REV-89", "HAS_CONTENT_REVISION", "CWE-89", revision.node_id)
    first = _merge_rebuild_details(
        store, collect_compact_detail_records([parent, revision], [relation]), (),
    )
    store.replace_all(first)
    second = _merge_rebuild_details(store, (), ())
    store.replace_all(second)

    assert store.canonical_revisions("CWE") == [revision]
    assert {item["detail_id"]: item for item in store.query()} == {
        item["detail_id"]: item for item in first
    }


def test_rebuild_replay_does_not_move_content_revision_availability(tmp_path) -> None:
    from scripts.rebuild_focused_graph import _merge_rebuild_details

    store = CompactDetailStore(tmp_path / "compact_details.sqlite3")
    old = _node(
        "CWEContentRevision", "REV-89",
        canonical_id="CWE-89", retrieved_at="2026-01-01T00:00:00+00:00",
    )
    replay = _node(
        "CWEContentRevision", "REV-89",
        canonical_id="CWE-89", retrieved_at="2026-03-01T00:00:00+00:00",
    )
    store.replace_all(collect_compact_detail_records([old], []))
    store.replace_all(_merge_rebuild_details(
        store, collect_compact_detail_records([replay], []), (),
    ))
    assert store.canonical_revisions("CWE") == [old]
