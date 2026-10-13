from __future__ import annotations

import os

import pytest

from db.sink import (
    DryRunSink,
    GraphRelationship,
    GraphSnapshot,
    Neo4jSink,
)


@pytest.fixture
def neo4j_test_sink() -> Neo4jSink:
    uri = os.environ.get("NEO4J_TEST_URI", "bolt://localhost:7688")
    user = os.environ.get("NEO4J_TEST_USER", "neo4j")
    password = os.environ.get("NEO4J_TEST_PASSWORD", "test-password")
    try:
        sink = Neo4jSink(uri, user, password)
    except Exception as exc:
        pytest.skip(f"neo4j-test is unavailable: {exc}")
    yield sink
    sink.run_write("MATCH (n) DETACH DELETE n")
    sink.close()


def _valid_snapshot() -> GraphSnapshot:
    stage = DryRunSink()
    stage.merge_node(
        "Weakness",
        "weaknessId",
        {"weaknessId": "LAB-1", "name": "New graph"},
    )
    stage.merge_node(
        "Technology", "name", {"name": "Python"}
    )
    stage.merge_rel(
        "Weakness",
        "weaknessId",
        "LAB-1",
        "AFFECTS_TECHNOLOGY",
        "Technology",
        "name",
        "Python",
        {"source": "test"},
    )
    return stage.snapshot()


def test_replace_graph_successfully_matches_staged_graph(
    neo4j_test_sink: Neo4jSink,
) -> None:
    neo4j_test_sink.run_write("MATCH (n) DETACH DELETE n")
    neo4j_test_sink.merge_node(
        "Weakness",
        "weaknessId",
        {"weaknessId": "OLD-1", "name": "Old graph"},
    )

    snapshot = _valid_snapshot()
    neo4j_test_sink.replace_graph(snapshot)

    assert neo4j_test_sink.get_node(
        "Weakness", "weaknessId", "OLD-1"
    ) is None
    assert neo4j_test_sink.get_node(
        "Weakness", "weaknessId", "LAB-1"
    )["name"] == "New graph"
    assert len(neo4j_test_sink.relationships()) == 1


def test_replace_rolls_back_on_relationship_failure(
    neo4j_test_sink: Neo4jSink,
) -> None:
    neo4j_test_sink.run_write("MATCH (n) DETACH DELETE n")
    neo4j_test_sink.merge_node(
        "Weakness",
        "weaknessId",
        {"weaknessId": "OLD-1", "name": "Old graph"},
    )
    valid = _valid_snapshot()
    missing_endpoint = GraphRelationship(
        from_label="Weakness",
        from_key="weaknessId",
        from_value="LAB-1",
        rel_type="AFFECTS_TECHNOLOGY",
        to_label="Technology",
        to_key="name",
        to_value="Missing",
        props={},
    )
    invalid = GraphSnapshot(
        nodes=valid.nodes,
        relationships=(*valid.relationships, missing_endpoint),
    )

    with pytest.raises(ValueError, match="missing endpoint"):
        neo4j_test_sink.replace_graph(invalid)

    old = neo4j_test_sink.get_node(
        "Weakness", "weaknessId", "OLD-1"
    )
    assert old is not None
    assert old["name"] == "Old graph"
    assert neo4j_test_sink.get_node(
        "Weakness", "weaknessId", "LAB-1"
    ) is None
