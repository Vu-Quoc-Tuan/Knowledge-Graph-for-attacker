from datetime import datetime, timezone

from ckg.graph.models import GraphEdge


def test_new_cwe_enrichment_creates_only_inferred_profile_candidates() -> None:
    from ckg.evolution.new_cwe import enrich_new_cwes
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="CWE", node_id="CWE-OLD", props={"name": "XML external entity parser", "description": "external XML entity", "status": "CANONICAL"}),
        GraphNode(label="CWE", node_id="CWE-NEW", props={"name": "XML entity processing", "description": "external XML entity parser", "status": "CANONICAL"}),
        GraphNode(label="CAPEC", node_id="CAPEC-TEST", props={}),
        GraphNode(label="TestStrategy", node_id="TSTRAT-TEST", props={}),
        GraphNode(label="CVE", node_id="CVE-2025-10000", props={}),
        GraphNode(label="WeaknessAssertion", node_id="WAS-OLD", props={}),
    ], edges=[
        GraphEdge(edge_id="CAPEC-MAPS", edge_type="RELATED_WEAKNESS", subject_id="CAPEC-TEST", object_id="CWE-NEW"),
        GraphEdge(edge_id="WSTG-MAPS", edge_type="TARGETS_WEAKNESS", subject_id="TSTRAT-TEST", object_id="CWE-NEW"),
        GraphEdge(edge_id="OLD-HAS-WAS", edge_type="HAS_WEAKNESS_ASSERTION", subject_id="CVE-2025-10000", object_id="WAS-OLD"),
        GraphEdge(edge_id="OLD-MAPS", edge_type="MAPS_TO", subject_id="WAS-OLD", object_id="CWE-OLD"),
    ])

    report = enrich_new_cwes(repository, ("CWE-NEW",))

    assert report.candidate_relation_count == 4
    candidates = repository.nodes("CandidateRelation")
    assert {candidate.props["status"] for candidate in candidates} == {"INFERRED"}
    assert {candidate.props["predicate"] for candidate in candidates} == {"SEMANTIC_NEIGHBOR", "CAPEC_NEIGHBOR_AVAILABLE", "TEST_STRATEGY_AVAILABLE", "HISTORICAL_CLUSTER_AVAILABLE"}
    assert {node.props["status"] for node in repository.nodes("CWE")} == {"CANONICAL"}
