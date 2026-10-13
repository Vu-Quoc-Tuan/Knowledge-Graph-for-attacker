import pytest


def test_canonical_relations_with_different_views_or_releases_do_not_merge() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode

    repository = InMemoryGraphRepository()
    repository.replace_all(
        nodes=[
            GraphNode(label="CWE", node_id="CWE-79", props={"name": "XSS"}),
            GraphNode(label="CWE", node_id="CWE-20", props={"name": "Input Validation"}),
        ],
        edges=[],
    )

    repository.atomic_write(
        nodes=[],
        edges=[
            GraphEdge(
                edge_id="CWE-REL-CWE-79-CHILDOF-CWE-20-VIEW-1000-R4.17",
                edge_type="CHILD_OF",
                subject_id="CWE-79",
                object_id="CWE-20",
                props={"view_id": "1000", "source_release": "4.17"},
            ),
            GraphEdge(
                edge_id="CWE-REL-CWE-79-CHILDOF-CWE-20-VIEW-699-R4.18",
                edge_type="CHILD_OF",
                subject_id="CWE-79",
                object_id="CWE-20",
                props={"view_id": "699", "source_release": "4.18"},
            ),
        ],
    )

    assert [edge.edge_id for edge in repository.edges("CHILD_OF")] == [
        "CWE-REL-CWE-79-CHILDOF-CWE-20-VIEW-1000-R4.17",
        "CWE-REL-CWE-79-CHILDOF-CWE-20-VIEW-699-R4.18",
    ]


def test_two_assertions_for_one_cve_and_cwe_are_retained() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[
            GraphNode(label="CVE", node_id="CVE-2026-0001", props={}),
            GraphNode(label="CWE", node_id="CWE-611", props={}),
            GraphNode(
                label="WeaknessAssertion",
                node_id="WAS-CVE-2026-0001-NVD-CWE-611",
                props={"source_id": "NVD-CVE-2026-0001"},
            ),
            GraphNode(
                label="WeaknessAssertion",
                node_id="WAS-CVE-2026-0001-GHSA-CWE-611",
                props={"source_id": "GHSA-2026-example"},
            ),
        ],
        edges=[],
    )

    assert len(repository.nodes("WeaknessAssertion")) == 2


def test_atomic_write_rolls_back_when_an_edge_endpoint_is_missing() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(
        nodes=[GraphNode(label="CWE", node_id="CWE-79", props={})], edges=[]
    )

    with pytest.raises(ValueError, match="missing endpoint"):
        repository.atomic_write(
            nodes=[GraphNode(label="CWE", node_id="CWE-20", props={})],
            edges=[
                GraphEdge(
                    edge_id="broken",
                    edge_type="CHILD_OF",
                    subject_id="CWE-20",
                    object_id="CWE-404",
                )
            ],
        )

    assert [node.node_id for node in repository.nodes("CWE")] == ["CWE-79"]


def test_existing_edge_identity_cannot_be_reused_for_different_endpoints() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="CWE", node_id="CWE-79", props={}),
        GraphNode(label="CWE", node_id="CWE-20", props={}),
        GraphNode(label="CWE", node_id="CWE-89", props={}),
    ], edges=[
        GraphEdge(edge_id="EDGE-1", edge_type="CHILD_OF", subject_id="CWE-79", object_id="CWE-20"),
    ])

    with pytest.raises(ValueError, match="edge identity collision"):
        repository.atomic_write(nodes=[], edges=[
            GraphEdge(edge_id="EDGE-1", edge_type="CHILD_OF", subject_id="CWE-79", object_id="CWE-89"),
        ])

    assert repository.edges()[0] == GraphEdge(edge_id="EDGE-1", edge_type="CHILD_OF", subject_id="CWE-79", object_id="CWE-20")


def test_storage_rejects_direct_vulnerability_to_cwe_relation() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="CVE", node_id="CVE-2026-0001", props={}),
        GraphNode(label="CWE", node_id="CWE-611", props={}),
    ], edges=[])

    with pytest.raises(ValueError, match="reified WeaknessAssertion"):
        repository.atomic_write(nodes=[], edges=[
            GraphEdge(edge_id="INVALID-DIRECT", edge_type="MAPS_TO", subject_id="CVE-2026-0001", object_id="CWE-611"),
        ])

    assert repository.edges() == []


def test_neo4j_property_codec_round_trips_nested_domain_data_and_metadata_keys() -> None:
    from ckg.graph.neo4j.driver import deserialize_properties, serialize_properties

    original = {
        "support": {"count": 2},
        "evidence_spans": [{"evidence_id": "EVID-1", "locator": "/cwe/0"}],
        "ids": ("EVID-1",),
        "kind": "vendor-advisory",
    }

    encoded = serialize_properties(original, reserved_keys=frozenset({"nodeId", "kind"}))

    assert encoded["ids"] == ["EVID-1"]
    assert "ckgV2Json" in encoded
    assert deserialize_properties(
        {**encoded, "nodeId": "N-1", "kind": "Evidence"},
        metadata_keys=frozenset({"nodeId", "kind"}),
    ) == {
        "support": {"count": 2},
        "evidence_spans": [{"evidence_id": "EVID-1", "locator": "/cwe/0"}],
        "ids": ["EVID-1"],
        "kind": "vendor-advisory",
    }


def test_file_evidence_store_round_trips_content_addressed_bytes(tmp_path) -> None:
    from ckg.graph.evidence_store.repository import FileEvidenceStore

    store = FileEvidenceStore(tmp_path)
    digest = store.put(b"immutable advisory bytes")

    assert digest == "sha256:05c3ea3737f0ae9cc70ae2d9a65428f4783680c5b1b0e86050f665b58893f979"
    assert store.get(digest) == b"immutable advisory bytes"
