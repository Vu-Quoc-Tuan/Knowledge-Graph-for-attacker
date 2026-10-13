from __future__ import annotations

import pytest

from ckg.application.focused_rebuild import (
    build_focused_projection,
    validate_focused_projection,
)
from ckg.graph.models import GraphEdge, GraphNode
from ckg.ingestion.wstg.catalog import store_canonical_wstg_snapshots
from ckg.provenance.store import SnapshotStore


def _node(label: str, node_id: str, **props: object) -> GraphNode:
    return GraphNode(label=label, node_id=node_id, props=dict(props))


def _edge(
    edge_id: str,
    edge_type: str,
    subject_id: str,
    object_id: str,
    **props: object,
) -> GraphEdge:
    return GraphEdge(
        edge_id=edge_id,
        edge_type=edge_type,
        subject_id=subject_id,
        object_id=object_id,
        props=props,
    )


def test_wstg_projection_keeps_only_directly_mapped_strategies() -> None:
    nodes = [
        _node("CWE", "CWE-22"),
        _node("CWE", "CWE-79"),
        _node("TestStrategy", "TSTRAT-FOCUSED"),
        _node("TestStrategy", "TSTRAT-SHARED-VOCAB"),
        _node("WSTGCase", "WSTG-FOCUSED"),
        _node("WSTGCase", "WSTG-UNRELATED"),
        _node("Technique", "TECH-SHARED"),
        _node("Evidence", "EVID-FOCUSED", content_digest="sha256:" + "a" * 64),
        _node("CVE", "CVE-2026-0001"),
        _node("WeaknessAssertion", "WAS-0001", all_source_snapshots_available=False),
        _node(
            "Evidence",
            "EVID-UNVERIFIED",
            content_digest="sha256:" + "b" * 64,
            source_snapshot_available=False,
        ),
    ]
    edges = [
        _edge("target-focused", "TARGETS_WEAKNESS", "TSTRAT-FOCUSED", "CWE-22"),
        _edge("target-unrelated", "TARGETS_WEAKNESS", "TSTRAT-SHARED-VOCAB", "CWE-79"),
        _edge("describe-focused", "DESCRIBES", "WSTG-FOCUSED", "TSTRAT-FOCUSED"),
        _edge("describe-unrelated", "DESCRIBES", "WSTG-UNRELATED", "TSTRAT-SHARED-VOCAB"),
        _edge("shared-focused", "USES_TECHNIQUE", "TSTRAT-FOCUSED", "TECH-SHARED"),
        _edge("shared-unrelated", "USES_TECHNIQUE", "TSTRAT-SHARED-VOCAB", "TECH-SHARED"),
        _edge("supported", "SUPPORTED_BY", "WSTG-FOCUSED", "EVID-FOCUSED"),
        _edge("has-assertion", "HAS_WEAKNESS_ASSERTION", "CVE-2026-0001", "WAS-0001"),
        _edge("maps", "MAPS_TO", "WAS-0001", "CWE-22"),
        _edge("unverified", "SUPPORTED_BY", "CVE-2026-0001", "EVID-UNVERIFIED"),
    ]

    selected_nodes, selected_edges, _ = build_focused_projection(
        nodes,
        edges,
        target_cwes=frozenset({"CWE-22"}),
    )
    selected_ids = {node.node_id for node in selected_nodes}

    assert "TSTRAT-FOCUSED" in selected_ids
    assert "WSTG-FOCUSED" in selected_ids
    assert "TECH-SHARED" in selected_ids
    assert "TSTRAT-SHARED-VOCAB" not in selected_ids
    assert "WSTG-UNRELATED" not in selected_ids
    assert "EVID-UNVERIFIED" not in selected_ids
    assert next(node for node in selected_nodes if node.node_id == "WAS-0001").props["stale"] is True
    validate_focused_projection(
        selected_nodes,
        selected_edges,
        target_cwes=frozenset({"CWE-22"}),
    )


def test_canonical_wstg_snapshots_are_replayable(tmp_path) -> None:
    store = SnapshotStore(tmp_path)
    digests = store_canonical_wstg_snapshots(store)

    assert len(digests) == 18
    for digest in digests.values():
        assert store.read(digest)


def test_validation_rejects_orphan_wstg_strategy() -> None:
    with pytest.raises(ValueError, match="without a focused TARGETS_WEAKNESS"):
        validate_focused_projection(
            [_node("CWE", "CWE-22"), _node("TestStrategy", "TSTRAT-ORPHAN")],
            [],
            target_cwes=frozenset({"CWE-22"}),
        )


def test_projection_drops_granular_patt_payload_nodes() -> None:
    nodes = [
        _node("CWE", "CWE-22"),
        _node("Payload", "PATT-PAYLOAD-OLD"),
        _node("PATTSection", "PATT-SECTION-OLD"),
        _node("PATTDocument", "PATT-DOCUMENT"),
        _node("AttackStep", "CAPEC-STEP"),
        _node("AttackPrerequisite", "CAPEC-PREREQ"),
        _node("CWECategory", "CWE-CATEGORY"),
        _node("CWEView", "CWE-VIEW"),
        _node("Evidence", "PATT-EVIDENCE", kind="patt_markdown"),
    ]
    edges = []
    selected_nodes, selected_edges, _ = build_focused_projection(
        nodes,
        edges,
        target_cwes=frozenset({"CWE-22"}),
    )
    assert {node.label for node in selected_nodes} == {"CWE"}
    assert selected_edges == []


def test_validation_rejects_granular_patt_payload_nodes() -> None:
    with pytest.raises(ValueError, match="granular PATT"):
        validate_focused_projection(
            [_node("CWE", "CWE-22"), _node("Payload", "PATT-PAYLOAD-OLD")],
            [],
            target_cwes=frozenset({"CWE-22"}),
        )


def test_validation_rejects_compacted_detail_nodes() -> None:
    for label, node_id, props in (
        ("AttackStep", "CAPEC-STEP", {}),
        ("CWECategory", "CWE-CATEGORY", {}),
        ("Evidence", "PATT-EVIDENCE", {"kind": "patt_markdown"}),
    ):
        with pytest.raises(ValueError, match="granular PATT"):
            validate_focused_projection(
                [_node("CWE", "CWE-22"), _node(label, node_id, **props)],
                [],
                target_cwes=frozenset({"CWE-22"}),
            )


def test_projection_compacts_multiview_hierarchy_edges_without_losing_source_ids() -> None:
    nodes = [_node("CWE", "CWE-79"), _node("CWE", "CWE-74")]
    digest = "sha256:" + "a" * 64
    edges = [
        _edge(
            "child-view-1000", "CHILD_OF", "CWE-79", "CWE-74",
            view_id="1000", source_release="4.20", source_snapshot_digest=digest,
            qualifier="Primary",
        ),
        _edge(
            "child-view-1003", "CHILD_OF", "CWE-79", "CWE-74",
            view_id="1003", source_release="4.20", source_snapshot_digest=digest,
            qualifier="Primary",
        ),
        _edge(
            "child-other-digest", "CHILD_OF", "CWE-79", "CWE-74",
            view_id="1305", source_release="4.20",
            source_snapshot_digest="sha256:" + "b" * 64,
            qualifier="Primary",
        ),
    ]

    selected_nodes, selected_edges, _ = build_focused_projection(
        nodes,
        edges,
        target_cwes=frozenset({"CWE-79", "CWE-74"}),
    )

    child_edges = [edge for edge in selected_edges if edge.edge_type == "CHILD_OF"]
    assert len(child_edges) == 2
    aggregated = next(edge for edge in child_edges if "view_ids" in edge.props)
    assert aggregated.props["view_ids"] == ["1000", "1003"]
    assert aggregated.props["source_edge_ids"] == ["child-view-1000", "child-view-1003"]
    assert aggregated.props["source_snapshot_digest"] == digest
    validate_focused_projection(
        selected_nodes,
        selected_edges,
        target_cwes=frozenset({"CWE-79", "CWE-74"}),
    )
