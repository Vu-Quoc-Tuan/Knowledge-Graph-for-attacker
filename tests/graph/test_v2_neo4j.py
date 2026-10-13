import os
from pathlib import Path

import pytest


@pytest.fixture
def repository():
    from ckg.graph.neo4j.driver import Neo4jGraphRepository

    uri = os.environ.get("NEO4J_V2_TEST_URI")
    if not uri:
        pytest.skip("set NEO4J_V2_TEST_URI to run v2 Neo4j parity tests")
    repo = Neo4jGraphRepository(
        uri,
        os.environ.get("NEO4J_V2_TEST_USER", "neo4j"),
        os.environ.get("NEO4J_V2_TEST_PASSWORD", "test-password"),
    )
    repo.apply_schema(str(Path("src/ckg/graph/neo4j/schema.cypher")))
    repo.replace_all(nodes=[], edges=[])
    yield repo
    repo.replace_all(nodes=[], edges=[])
    repo.close()


def test_neo4j_retains_distinct_edge_ids_for_the_same_endpoint_pair(repository) -> None:
    from ckg.graph.models import GraphEdge, GraphNode

    repository.atomic_write(
        nodes=[
            GraphNode(label="CWE", node_id="CWE-79", props={"name": "XSS"}),
            GraphNode(label="CWE", node_id="CWE-20", props={"name": "Validation"}),
        ],
        edges=[
            GraphEdge(
                edge_id="CWE-REL-1000",
                edge_type="CHILD_OF",
                subject_id="CWE-79",
                object_id="CWE-20",
                props={"view_id": "1000", "source_release": "4.17"},
            ),
            GraphEdge(
                edge_id="CWE-REL-699",
                edge_type="CHILD_OF",
                subject_id="CWE-79",
                object_id="CWE-20",
                props={"view_id": "699", "source_release": "4.18"},
            ),
        ],
    )

    assert [edge.edge_id for edge in repository.edges("CHILD_OF")] == [
        "CWE-REL-1000",
        "CWE-REL-699",
    ]


def test_neo4j_technology_search_filters_versions_by_product(repository) -> None:
    from ckg.graph.models import GraphEdge, GraphNode

    repository.atomic_write(
        nodes=[
            GraphNode(label="CVE", node_id="CVE-2026-0300", props={"published_at": "2026-01-01T00:00:00+00:00"}),
            GraphNode(label="Product", node_id="PRODUCT-ALPHA", props={"name": "Alpha"}),
            GraphNode(label="Product", node_id="PRODUCT-BETA", props={"name": "Beta"}),
            GraphNode(label="VersionRange", node_id="VERSION-ALPHA", props={"expression": "< 2"}),
            GraphNode(label="VersionRange", node_id="VERSION-BETA", props={"expression": ">= 3"}),
            GraphNode(label="VersionRange", node_id="VERSION-LEGACY", props={"expression": "all"}),
        ],
        edges=[
            GraphEdge(edge_id="A-ALPHA", edge_type="AFFECTS", subject_id="CVE-2026-0300", object_id="PRODUCT-ALPHA"),
            GraphEdge(edge_id="A-BETA", edge_type="AFFECTS", subject_id="CVE-2026-0300", object_id="PRODUCT-BETA"),
            GraphEdge(edge_id="V-ALPHA", edge_type="AFFECTS_VERSION", subject_id="CVE-2026-0300", object_id="VERSION-ALPHA", props={"product_ids": ["PRODUCT-ALPHA"]}),
            GraphEdge(edge_id="V-BETA", edge_type="AFFECTS_VERSION", subject_id="CVE-2026-0300", object_id="VERSION-BETA", props={"product_ids": ["PRODUCT-BETA"]}),
            GraphEdge(edge_id="V-LEGACY", edge_type="AFFECTS_VERSION", subject_id="CVE-2026-0300", object_id="VERSION-LEGACY"),
        ],
    )

    alpha = repository.search_vulnerabilities("Alpha", from_year=2026, to_year=2026)
    beta = repository.search_vulnerabilities("Beta", from_year=2026, to_year=2026)
    assert {version.node_id for version in alpha[0].versions} == {"VERSION-ALPHA", "VERSION-LEGACY"}
    assert {version.node_id for version in beta[0].versions} == {"VERSION-BETA", "VERSION-LEGACY"}


def test_neo4j_atomic_write_rolls_back_on_missing_endpoint(repository) -> None:
    from ckg.graph.models import GraphEdge, GraphNode

    repository.atomic_write(
        nodes=[GraphNode(label="CWE", node_id="CWE-79", props={})], edges=[]
    )

    with pytest.raises(ValueError, match="missing endpoint"):
        repository.atomic_write(
            nodes=[GraphNode(label="CWE", node_id="CWE-20", props={})],
            edges=[
                GraphEdge(
                    edge_id="CWE-REL-BROKEN",
                    edge_type="CHILD_OF",
                    subject_id="CWE-20",
                    object_id="CWE-404",
                )
            ],
        )

    assert [node.node_id for node in repository.nodes("CWE")] == ["CWE-79"]


def test_neo4j_atomic_write_is_idempotent_by_node_and_edge_identity(repository) -> None:
    from ckg.graph.models import GraphEdge, GraphNode

    nodes = [
        GraphNode(label="CVE", node_id="CVE-2026-0001", props={}),
        GraphNode(
            label="WeaknessAssertion",
            node_id="WAS-CVE-2026-0001-NVD-CWE-611",
            props={"source_id": "NVD-CVE-2026-0001"},
        ),
        GraphNode(label="CWE", node_id="CWE-611", props={}),
    ]
    edges = [
        GraphEdge(
            edge_id="EDGE-CVE-2026-0001-HAS-WAS-NVD",
            edge_type="HAS_WEAKNESS_ASSERTION",
            subject_id="CVE-2026-0001",
            object_id="WAS-CVE-2026-0001-NVD-CWE-611",
        ),
        GraphEdge(
            edge_id="EDGE-WAS-NVD-MAPS-CWE-611",
            edge_type="MAPS_TO",
            subject_id="WAS-CVE-2026-0001-NVD-CWE-611",
            object_id="CWE-611",
        ),
    ]

    repository.atomic_write(nodes=nodes, edges=edges)
    repository.atomic_write(nodes=nodes, edges=edges)

    assert len(repository.nodes()) == 3
    assert len(repository.edges()) == 2


def test_neo4j_rejects_reusing_an_edge_id_for_different_endpoints(repository) -> None:
    from ckg.graph.models import GraphEdge, GraphNode

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


def test_neo4j_rejects_direct_vulnerability_to_cwe_relation(repository) -> None:
    from ckg.graph.models import GraphEdge, GraphNode

    repository.atomic_write(nodes=[
        GraphNode(label="CVE", node_id="CVE-2026-0001", props={}),
        GraphNode(label="CWE", node_id="CWE-611", props={}),
    ], edges=[])

    with pytest.raises(ValueError, match="reified WeaknessAssertion"):
        repository.atomic_write(nodes=[], edges=[
            GraphEdge(edge_id="INVALID-DIRECT", edge_type="MAPS_TO", subject_id="CVE-2026-0001", object_id="CWE-611"),
        ])

    assert repository.edges() == []


def test_neo4j_round_trips_real_assertion_provenance_and_evidence_spans(repository) -> None:
    from ckg.domain.entities.assertion import WeaknessAssertion
    from ckg.domain.enums.fact_status import FactStatus
    from ckg.domain.value_objects.evidence_span import EvidenceSpan
    from ckg.domain.value_objects.provenance import Provenance
    from ckg.graph.models import GraphNode

    assertion = WeaknessAssertion(
        assertion_id="WAS-CVE-2026-0001-CWE-611",
        vulnerability_id="CVE-2026-0001",
        cwe_id="CWE-611",
        status=FactStatus.REPORTED,
        provenance=Provenance(
            source_id="SRCREC-nvd-1",
            source_kind="nvd",
            retrieved_at="2026-01-01T00:00:00Z",
        ),
        evidence_spans=(
            EvidenceSpan(
                evidence_id="EVID-nvd-1",
                content_digest="sha256:" + "a" * 64,
                locator="/weaknesses/0",
            ),
        ),
    )
    repository.atomic_write(
        nodes=[
            GraphNode(
                label="WeaknessAssertion",
                node_id=assertion.assertion_id,
                props=assertion.model_dump(mode="json", exclude_none=True),
            )
        ],
        edges=[],
    )

    assert repository.nodes("WeaknessAssertion")[0].props == assertion.model_dump(
        mode="json", exclude_none=True
    )


def test_neo4j_pushes_down_local_subgraph_budget(repository) -> None:
    from ckg.graph.models import GraphEdge, GraphNode
    from ckg.reasoning.subgraph.budgets import SubgraphBudget
    from ckg.reasoning.subgraph.builder import build_local_subgraph

    repository.atomic_write(
        nodes=[
            GraphNode(label="CVE", node_id="CVE-2026-0002", props={"published_at": "2026-01-01T00:00:00+00:00"}),
            GraphNode(label="WeaknessAssertion", node_id="WAS-1", props={}),
            GraphNode(label="CWE", node_id="CWE-1", props={}),
            GraphNode(label="CWE", node_id="CWE-2", props={}),
        ],
        edges=[
            GraphEdge(edge_id="EDGE-1", edge_type="HAS_WEAKNESS_ASSERTION", subject_id="CVE-2026-0002", object_id="WAS-1"),
            GraphEdge(edge_id="EDGE-2", edge_type="MAPS_TO", subject_id="WAS-1", object_id="CWE-1"),
            GraphEdge(edge_id="EDGE-3", edge_type="MAPS_TO", subject_id="WAS-1", object_id="CWE-2"),
        ],
    )

    result = build_local_subgraph(repository, "CVE-2026-0002", budget=SubgraphBudget(hard_max_nodes=3, cwe=2, max_depth=2))

    assert {node.node_id for node in result.nodes} == {"CVE-2026-0002", "WAS-1", "CWE-1"}
    assert result.truncated is True


def test_neo4j_searches_product_backed_cves_by_technology_and_year(repository) -> None:
    from ckg.graph.models import GraphEdge, GraphNode

    repository.atomic_write(
        nodes=[
            GraphNode(
                label="CVE",
                node_id="CVE-2026-0003",
                props={"title": "Grafana issue", "published_at": "2026-01-01T00:00:00+00:00"},
            ),
            GraphNode(
                label="CVE",
                node_id="CVE-2026-0004",
                props={"title": "Vendor issue", "published_at": "2026-01-02T00:00:00+00:00"},
            ),
            GraphNode(
                label="CVE",
                node_id="CVE-2022-0005",
                props={"title": "Old issue", "published_at": "2022-01-01T00:00:00+00:00"},
            ),
            GraphNode(label="Product", node_id="PRODUCT-GRAFANA", props={"name": "grafana", "vendor": "grafana"}),
            GraphNode(label="Product", node_id="PRODUCT-DASHBOARD", props={"name": "dashboard", "vendor": "grafana"}),
            GraphNode(label="Product", node_id="PRODUCT-OLD", props={"name": "grafana-old", "vendor": "grafana"}),
        ],
        edges=[
            GraphEdge(edge_id="EDGE-SEARCH-1", edge_type="AFFECTS", subject_id="CVE-2026-0003", object_id="PRODUCT-GRAFANA"),
            GraphEdge(edge_id="EDGE-SEARCH-2", edge_type="AFFECTS", subject_id="CVE-2026-0004", object_id="PRODUCT-DASHBOARD"),
            GraphEdge(edge_id="EDGE-SEARCH-3", edge_type="AFFECTS", subject_id="CVE-2022-0005", object_id="PRODUCT-OLD"),
        ],
    )

    matches = repository.search_vulnerabilities(
        " Grafana ", from_year=2025, to_year=2026, limit=10
    )

    assert [match.vulnerability.node_id for match in matches] == [
        "CVE-2026-0003",
        "CVE-2026-0004",
    ]
    assert matches[0].match_reason == "exact_product"
    assert matches[0].relevance > matches[1].relevance
