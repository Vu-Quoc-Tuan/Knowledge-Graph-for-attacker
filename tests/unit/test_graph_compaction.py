import hashlib

from ckg.graph.models import GraphEdge, GraphNode
from ckg.provenance.graph_compaction import (
    affects_version_edge_id,
    compact_version_ranges,
    version_range_id,
)


def _range(node_id: str, *, ecosystem: str = "cpe", expression: str = "< 2", status: str = "affected", **props) -> GraphNode:
    return GraphNode(
        label="VersionRange", node_id=node_id,
        props={"ecosystem": ecosystem, "expression": expression, "status": status, **props},
    )


def _edge(edge_id: str, edge_type: str, subject: str, target: str, **props) -> GraphEdge:
    return GraphEdge(edge_id=edge_id, edge_type=edge_type, subject_id=subject, object_id=target, props=props)


def _legacy_id(product_id: str, expression: str = "< 2", status: str = "affected") -> str:
    return "VERSION-RANGE-" + hashlib.sha256(f"{product_id}\x1f{expression}\x1f{status}".encode()).hexdigest()[:24]


def test_compacts_only_equal_semantic_ranges_and_keeps_product_provenance() -> None:
    old_1 = _legacy_id("P1")
    old_2 = _legacy_id("P2")
    nodes = [
        GraphNode(label="CVE", node_id="CVE-1", props={}),
        GraphNode(label="Product", node_id="P1", props={}),
        GraphNode(label="Product", node_id="P2", props={}),
        _range(old_1, source_pointer="/affected/0", confidence=0.8),
        _range(old_2, source_pointer="/affected/1", confidence=0.9),
        _range("different-status", status="fixed"),
        _range("different-ecosystem", ecosystem="PIP"),
        _range("different-expression", expression="< 3"),
    ]
    edges = [
        _edge("a1", "AFFECTS", "CVE-1", "P1", source_record_id="S1", source_pointer="/affected/0"),
        _edge("a2", "AFFECTS", "CVE-1", "P2", source_record_id="S1", source_pointer="/affected/1"),
        _edge("v1", "AFFECTS_VERSION", "CVE-1", old_1, source_record_id="S1", reviewed_at="2026-01-01"),
        _edge("v2", "AFFECTS_VERSION", "CVE-1", old_2, source_record_id="S1", reviewed_at="2026-01-02"),
        _edge("v3", "AFFECTS_VERSION", "CVE-1", "different-status", source_record_id="S1"),
        _edge("v4", "AFFECTS_VERSION", "CVE-1", "different-ecosystem", source_record_id="S1"),
        _edge("v5", "AFFECTS_VERSION", "CVE-1", "different-expression", source_record_id="S1"),
    ]

    result_nodes, result_edges, report = compact_version_ranges(nodes, edges)

    assert report.original_version_range_count == 5
    assert report.compacted_version_range_count == 4
    assert report.original_affects_version_count == 5
    assert report.compacted_affects_version_count == 4
    canonical_id = version_range_id("cpe", "< 2", "affected")
    canonical = next(node for node in result_nodes if node.node_id == canonical_id)
    assert canonical.props["original_node_ids"] == sorted([old_1, old_2])
    assert {record["props"]["confidence"] for record in canonical.props["original_nodes"]} == {0.8, 0.9}
    assert canonical.props["source_pointers"] == ["/affected/0", "/affected/1"]
    relation = next(edge for edge in result_edges if edge.object_id == canonical_id)
    assert relation.edge_id == affects_version_edge_id("CVE-1", canonical_id, "S1")
    assert relation.props["original_edge_ids"] == ["v1", "v2"]
    assert {record["props"]["reviewed_at"] for record in relation.props["original_edges"]} == {"2026-01-01", "2026-01-02"}
    assert relation.props["product_ids"] == ["P1", "P2"]
    assert {(item["product_id"], item["source_pointer"]) for item in relation.props["product_associations"]} == {
        ("P1", "/affected/0"), ("P2", "/affected/1")
    }
    assert len({node.node_id for node in result_nodes}) == len(result_nodes)
    assert len({edge.edge_id for edge in result_edges}) == len(result_edges)
    assert [edge.object_id for edge in result_edges if edge.edge_id in {"v3", "v4", "v5"}] == []
    assert compact_version_ranges(result_nodes, result_edges)[:2] == (result_nodes, result_edges)
    assert compact_version_ranges(reversed(nodes), reversed(edges)) == (result_nodes, result_edges, report)


def test_different_sources_stay_distinct_and_missing_product_is_not_guessed() -> None:
    nodes = [
        _range("old-1", source_pointer="/one"),
        _range("old-2", source_pointer="/two"),
    ]
    edges = [
        _edge("v1", "AFFECTS_VERSION", "CVE-1", "old-1", source_record_id="S1"),
        _edge("v2", "AFFECTS_VERSION", "CVE-1", "old-2", source_record_id="S2"),
    ]

    _, compacted_edges, report = compact_version_ranges(nodes, edges)

    assert report.compacted_affects_version_count == 2
    assert {edge.props["source_record_id"] for edge in compacted_edges} == {"S1", "S2"}
    assert all(edge.props["product_ids"] == [] for edge in compacted_edges)
    assert {item["original_node_id"] for edge in compacted_edges for item in edge.props["product_associations"]} == {"old-1", "old-2"}


def test_old_product_based_identity_restores_product_when_pointer_is_stale() -> None:
    old_id = _legacy_id("P1")
    nodes = [_range(old_id, source_pointer="/stale")]
    edges = [
        _edge("a1", "AFFECTS", "CVE-1", "P1", source_record_id="S2", source_pointer="/new"),
        _edge("v1", "AFFECTS_VERSION", "CVE-1", old_id, source_record_id="S2"),
    ]

    _, compacted_edges, _ = compact_version_ranges(nodes, edges)

    version_edge = next(edge for edge in compacted_edges if edge.edge_type == "AFFECTS_VERSION")
    assert version_edge.props["product_ids"] == ["P1"]
    assert version_edge.props["source_pointers"] == ["/stale"]
    assert version_edge.props["product_associations"][0]["source_pointer"] is None


def test_incomplete_semantic_key_fails_closed() -> None:
    try:
        compact_version_ranges([GraphNode(label="VersionRange", node_id="bad", props={"expression": "< 2"})], [])
    except ValueError as error:
        assert "incomplete semantic key" in str(error)
    else:
        raise AssertionError("incomplete VersionRange should not be compacted")


def test_source_less_relations_remain_separate() -> None:
    nodes = [_range("old-1"), _range("old-2")]
    edges = [
        _edge("v1", "AFFECTS_VERSION", "CVE-1", "old-1", note="first"),
        _edge("v2", "AFFECTS_VERSION", "CVE-1", "old-2", note="second"),
    ]

    _, compacted_edges, report = compact_version_ranges(nodes, edges)

    assert report.compacted_affects_version_count == 2
    assert {edge.edge_id for edge in compacted_edges} == {"v1", "v2"}
    assert {record["props"]["note"] for edge in compacted_edges for record in edge.props["original_edges"]} == {"first", "second"}


def test_compacted_metadata_round_trips_through_neo4j_property_codec() -> None:
    from ckg.graph.neo4j.driver import deserialize_properties, serialize_properties

    nodes = [_range("old-1", source_pointer="/a"), _range("old-2", source_pointer="/b")]
    edges = [
        _edge("v1", "AFFECTS_VERSION", "CVE-1", "old-1", source_record_id="S1", product_id="P1", source_pointer="/a"),
        _edge("v2", "AFFECTS_VERSION", "CVE-1", "old-2", source_record_id="S1", product_id="P2", source_pointer="/b"),
    ]

    compacted_nodes, compacted_edges, _ = compact_version_ranges(nodes, edges)
    range_props = compacted_nodes[0].props
    edge_props = compacted_edges[0].props

    assert deserialize_properties(serialize_properties(range_props), metadata_keys=frozenset()) == range_props
    assert deserialize_properties(serialize_properties(edge_props), metadata_keys=frozenset()) == edge_props


def test_single_canonical_version_edge_uses_shared_association_contract() -> None:
    canonical_id = version_range_id("cpe", "< 2", "affected")
    nodes = [_range(canonical_id)]
    edges = [_edge(
        affects_version_edge_id("CVE-1", canonical_id, "S1"),
        "AFFECTS_VERSION", "CVE-1", canonical_id,
        source_record_id="S1", product_id="P1", source_pointer="/affected/0",
    )]

    compacted_nodes, compacted_edges, _ = compact_version_ranges(nodes, edges)
    relation = compacted_edges[0]
    assert relation.props["product_ids"] == ["P1"]
    assert relation.props["source_pointers"] == ["/affected/0"]
    assert relation.props["product_associations"] == [{
        "product_id": "P1", "source_pointer": "/affected/0",
        "original_node_id": canonical_id, "original_edge_id": edges[0].edge_id,
    }]
    assert compact_version_ranges(compacted_nodes, compacted_edges)[:2] == (compacted_nodes, compacted_edges)
