from datetime import datetime, timezone


def test_historical_candidates_load_canonical_revisions_once_per_catalog() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode
    from ckg.linking.historical.candidate_generator import historical_candidate_sources

    class CountingRepository(InMemoryGraphRepository):
        def __init__(self):
            super().__init__()
            self.node_reads = 0
            self.edge_reads = 0

        def nodes(self, label=None):
            self.node_reads += 1
            return super().nodes(label)

        def edges(self, edge_type=None):
            self.edge_reads += 1
            return super().edges(edge_type)

    repository = CountingRepository()
    repository.atomic_write(
        nodes=[
            GraphNode(label="CVE", node_id="CVE-2026-1", props={}),
            GraphNode(label="CWE", node_id="CWE-79", props={}),
            GraphNode(
                label="CWEContentRevision",
                node_id="CWE-REV-79",
                props={
                    "canonical_id": "CWE-79",
                    "retrieved_at": "2026-01-01T00:00:00+00:00",
                    "source_release": "4.20",
                },
            ),
        ],
        edges=[
            GraphEdge(
                edge_id=f"EDGE-{index}",
                edge_type="CHILD_OF",
                subject_id="CWE-79",
                object_id="CWE-79",
                props={"source_release": "4.20"},
            )
            for index in range(20)
        ],
    )

    historical_candidate_sources(repository, "CVE-2026-1")

    assert repository.node_reads == 3
    assert repository.edge_reads == 1


def _node(label, node_id, **props):
    from ckg.graph.models import GraphNode
    return GraphNode(label=label, node_id=node_id, props=props)


def _edge(edge_id, edge_type, source, target):
    from ckg.graph.models import GraphEdge
    return GraphEdge(edge_id=edge_id, edge_type=edge_type, subject_id=source, object_id=target)


def test_historical_retrieval_unions_weakness_technique_context_and_graph_sources() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.linking.historical.hybrid_retriever import retrieve_historical_neighbors

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001", published_at="2026-01-01T00:00:00+00:00"),
        _node("CVE", "CVE-2025-10001", published_at="2025-01-01T00:00:00+00:00"),
        _node("CVE", "CVE-2024-10001", published_at="2024-01-01T00:00:00+00:00"),
        _node("CVE", "CVE-2027-10001", published_at="2027-01-01T00:00:00+00:00"),
        _node("WeaknessAssertion", "W1", retrieved_at="2026-01-01T00:00:00+00:00"), _node("WeaknessAssertion", "W2", retrieved_at="2025-01-01T00:00:00+00:00"), _node("WeaknessAssertion", "W3", retrieved_at="2024-01-01T00:00:00+00:00"),
        _node("TechniqueAssertion", "T1", retrieved_at="2026-01-01T00:00:00+00:00"), _node("TechniqueAssertion", "T2", retrieved_at="2025-01-01T00:00:00+00:00"),
        _node("ContextAssertion", "C1", retrieved_at="2026-01-01T00:00:00+00:00"), _node("ContextAssertion", "C2", retrieved_at="2025-01-01T00:00:00+00:00"),
        _node("CWE", "CWE-611"), _node("CWE", "CWE-827"), _node("Technique", "TECH-OUT_OF_BAND"), _node("Protocol", "PROTOCOL-DNS", retrieved_at="2025-01-01T00:00:00+00:00"),
        _node("CAPEC", "CAPEC-1"), _node("PatchPattern", "PATCH-SAFE-PARSER"),
    ], edges=[
        _edge("1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10001", "W1"), _edge("2", "MAPS_TO", "W1", "CWE-611"),
        _edge("3", "HAS_TECHNIQUE_ASSERTION", "CVE-2026-10001", "T1"), _edge("4", "MAPS_TO", "T1", "TECH-OUT_OF_BAND"),
        _edge("5", "HAS_CONTEXT_ASSERTION", "CVE-2026-10001", "C1"), _edge("6", "MAPS_TO", "C1", "PROTOCOL-DNS"),
        _edge("7", "HAS_WEAKNESS_ASSERTION", "CVE-2025-10001", "W2"), _edge("8", "MAPS_TO", "W2", "CWE-611"),
        _edge("9", "HAS_TECHNIQUE_ASSERTION", "CVE-2025-10001", "T2"), _edge("10", "MAPS_TO", "T2", "TECH-OUT_OF_BAND"),
        _edge("11", "HAS_CONTEXT_ASSERTION", "CVE-2025-10001", "C2"), _edge("12", "MAPS_TO", "C2", "PROTOCOL-DNS"),
        _edge("13", "HAS_WEAKNESS_ASSERTION", "CVE-2024-10001", "W3"), _edge("14", "MAPS_TO", "W3", "CWE-827"),
        _edge("15", "PEER_OF", "CWE-611", "CWE-827"),
        _edge("16", "SIMILAR_TO", "CVE-2026-10001", "CVE-2024-10001"),
        _edge("17", "SIMILAR_TO", "CVE-2026-10001", "CVE-2027-10001"),
        _edge("18", "RELATED_WEAKNESS", "CAPEC-1", "CWE-611"),
        _edge("19", "HAS_PATCH_PATTERN", "CVE-2026-10001", "PATCH-SAFE-PARSER"),
        _edge("20", "HAS_PATCH_PATTERN", "CVE-2025-10001", "PATCH-SAFE-PARSER"),
    ])

    results = retrieve_historical_neighbors(repository, "CVE-2026-10001", as_of=datetime(2026, 9, 14, tzinfo=timezone.utc))

    assert [item.vulnerability_id for item in results] == ["CVE-2025-10001", "CVE-2024-10001"]
    assert results[0].sources == frozenset({"same_weakness", "same_technique", "same_context", "same_capec_neighborhood", "same_patch_pattern"})
    assert results[1].sources == frozenset({"adjacent_weakness", "graph_similarity"})


def test_historical_retrieval_excludes_late_assertion_even_when_its_cve_is_old() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.linking.historical.hybrid_retriever import retrieve_historical_neighbors

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001", published_at="2026-01-01T00:00:00+00:00"), _node("CVE", "CVE-2025-10001", published_at="2025-01-01T00:00:00+00:00"),
        _node("WeaknessAssertion", "W-CURRENT", retrieved_at="2026-01-01T00:00:00+00:00"), _node("WeaknessAssertion", "W-LATE", retrieved_at="2027-01-01T00:00:00+00:00"),
        _node("CWE", "CWE-611"),
    ], edges=[
        _edge("1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10001", "W-CURRENT"), _edge("2", "MAPS_TO", "W-CURRENT", "CWE-611"),
        _edge("3", "HAS_WEAKNESS_ASSERTION", "CVE-2025-10001", "W-LATE"), _edge("4", "MAPS_TO", "W-LATE", "CWE-611"),
    ])

    assert retrieve_historical_neighbors(repository, "CVE-2026-10001", as_of=datetime(2026, 9, 14, tzinfo=timezone.utc)) == ()


def test_historical_retrieval_ignores_missing_evidence_and_custom_examples() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.linking.historical.hybrid_retriever import retrieve_historical_neighbors

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001"),
        _node("CVE", "CVE-2025-10001"),
        _node("CVE", "CVE-2024-10001"),
        _node("CVE", "CVE-2023-10001"),
        _node("WeaknessAssertion", "W-TARGET", evidence_spans=[]),
        _node("WeaknessAssertion", "W-MISSING", evidence_spans=[{"evidence_id": "EVID-ABSENT"}]),
        _node("WeaknessAssertion", "W-CUSTOM", evidence_spans=[]),
        _node("WeaknessAssertion", "W-VALID", evidence_spans=[]),
        _node("VulnerabilitySourceRecord", "SRC-CUSTOM", source_url="custom://CVE-2024-10001"),
        _node("CWE", "CWE-89"),
    ], edges=[
        _edge("a", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10001", "W-TARGET"),
        _edge("b", "MAPS_TO", "W-TARGET", "CWE-89"),
        _edge("c", "HAS_WEAKNESS_ASSERTION", "CVE-2025-10001", "W-MISSING"),
        _edge("d", "MAPS_TO", "W-MISSING", "CWE-89"),
        _edge("e", "HAS_WEAKNESS_ASSERTION", "CVE-2024-10001", "W-CUSTOM"),
        _edge("f", "MAPS_TO", "W-CUSTOM", "CWE-89"),
        _edge("g", "DESCRIBES", "SRC-CUSTOM", "CVE-2024-10001"),
        _edge("h", "HAS_WEAKNESS_ASSERTION", "CVE-2023-10001", "W-VALID"),
        _edge("i", "MAPS_TO", "W-VALID", "CWE-89"),
    ])

    assert [item.vulnerability_id for item in retrieve_historical_neighbors(repository, "CVE-2026-10001")] == ["CVE-2023-10001"]


def test_vector_baseline_ranks_locally_without_provider_or_network() -> None:
    from ckg.graph.vectors import InMemoryVectorIndex, lexical_embedding

    index = InMemoryVectorIndex()
    index.upsert("xml", lexical_embedding("blind xml external entity dns"))
    index.upsert("sql", lexical_embedding("sql database injection"))

    assert index.search(lexical_embedding("xml dns"), top_k=1)[0][0] == "xml"
