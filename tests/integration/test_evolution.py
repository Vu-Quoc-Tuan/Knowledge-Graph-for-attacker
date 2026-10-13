from datetime import datetime, timezone


def _node(label, node_id, **props):
    from ckg.graph.models import GraphNode
    return GraphNode(label=label, node_id=node_id, props=props)


def _edge(edge_id, edge_type, source, target):
    from ckg.graph.models import GraphEdge
    return GraphEdge(edge_id=edge_id, edge_type=edge_type, subject_id=source, object_id=target)


def test_global_maintenance_reads_graph_once_instead_of_once_per_vulnerability() -> None:
    from ckg.evolution.cooccurrence import mine_cooccurrence
    from ckg.evolution.cwe_profiler import rebuild_cwe_profiles
    from ckg.graph.memory import InMemoryGraphRepository

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
            _node("CVE", "CVE-2026-1"),
            _node("CVE", "CVE-2026-2"),
            _node("CWE", "CWE-89"),
            _node("WeaknessAssertion", "W-1"),
            _node("WeaknessAssertion", "W-2"),
        ],
        edges=[
            _edge("1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-1", "W-1"),
            _edge("2", "MAPS_TO", "W-1", "CWE-89"),
            _edge("3", "HAS_WEAKNESS_ASSERTION", "CVE-2026-2", "W-2"),
            _edge("4", "MAPS_TO", "W-2", "CWE-89"),
        ],
    )

    rebuild_cwe_profiles(repository)
    assert (repository.node_reads, repository.edge_reads) == (1, 1)

    repository.node_reads = repository.edge_reads = 0
    mine_cooccurrence(repository)
    assert (repository.node_reads, repository.edge_reads) == (1, 1)


def test_profiles_aggregate_without_mutating_canonical_cwe_and_aliases_do_not_double_count() -> None:
    from ckg.evolution.cwe_profiler import rebuild_cwe_profiles
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CWE", "CWE-611", status="CANONICAL", name="XXE"),
        _node("CVE", "CVE-2026-1"), _node("GHSA", "GHSA-a-b-c"),
        _node("WeaknessAssertion", "W-CVE"), _node("WeaknessAssertion", "W-GHSA"),
        _node("TechniqueAssertion", "T-CVE"), _node("Technique", "TECH-OUT_OF_BAND"),
    ], edges=[
        _edge("1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-1", "W-CVE"), _edge("2", "MAPS_TO", "W-CVE", "CWE-611"),
        _edge("3", "HAS_WEAKNESS_ASSERTION", "GHSA-a-b-c", "W-GHSA"), _edge("4", "MAPS_TO", "W-GHSA", "CWE-611"),
        _edge("5", "ALIAS_OF", "GHSA-a-b-c", "CVE-2026-1"),
        _edge("6", "HAS_TECHNIQUE_ASSERTION", "CVE-2026-1", "T-CVE"), _edge("7", "MAPS_TO", "T-CVE", "TECH-OUT_OF_BAND"),
    ])

    report = rebuild_cwe_profiles(repository)
    profile = repository.nodes("CWEContextProfile")[0]

    assert report.profile_count == 1
    assert profile.props["independent_vulnerability_count"] == 1
    assert repository.nodes("CWE")[0].props["status"] == "CANONICAL"
    assert repository.nodes("ProfileAssociation")[0].props["support"] == 1


def test_cooccurrence_is_observed_noncausal_and_candidate_lifecycle_is_explicit() -> None:
    from ckg.domain.enums.fact_status import FactStatus
    from ckg.evolution.candidate_lifecycle import advance, transition_candidate
    from ckg.evolution.cooccurrence import mine_cooccurrence
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-1"), _node("CVE", "CVE-2026-2"), _node("CWE", "CWE-79"), _node("CWE", "CWE-89"),
        _node("WeaknessAssertion", "A1"), _node("WeaknessAssertion", "B1"), _node("WeaknessAssertion", "A2"), _node("WeaknessAssertion", "B2"),
    ], edges=[
        _edge("1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-1", "A1"), _edge("2", "MAPS_TO", "A1", "CWE-79"), _edge("3", "HAS_WEAKNESS_ASSERTION", "CVE-2026-1", "B1"), _edge("4", "MAPS_TO", "B1", "CWE-89"),
        _edge("5", "HAS_WEAKNESS_ASSERTION", "CVE-2026-2", "A2"), _edge("6", "MAPS_TO", "A2", "CWE-79"), _edge("7", "HAS_WEAKNESS_ASSERTION", "CVE-2026-2", "B2"), _edge("8", "MAPS_TO", "B2", "CWE-89"),
    ])

    report = mine_cooccurrence(repository, min_support=2)

    assert report.relation_count == 1
    assert repository.nodes("Cooccurrence")[0].props["semantic"] == "non_causal_observation"
    assert advance(FactStatus.INFERRED, independent_evidence_count=2) == FactStatus.SUPPORTED
    assert advance(FactStatus.SUPPORTED, independent_evidence_count=2, verified=True) == FactStatus.VALIDATED
    assert advance(FactStatus.SUPPORTED, independent_evidence_count=2, rejected=True) == FactStatus.REJECTED
    assert advance(FactStatus.VALIDATED, independent_evidence_count=0) == FactStatus.VALIDATED
    assert advance(FactStatus.REJECTED, independent_evidence_count=99, verified=True) == FactStatus.REJECTED

    repository.atomic_write(nodes=[_node("CandidateRelation", "INFERRED-1", status="INFERRED")], edges=[])
    transition = transition_candidate(repository, candidate_id="INFERRED-1", independent_evidence_count=2, transitioned_at=datetime(2026, 9, 14, tzinfo=timezone.utc))
    assert transition.current_status == FactStatus.SUPPORTED
    assert repository.nodes("CandidateStatusEvent")[0].props["previous_status"] == "INFERRED"
    no_op = transition_candidate(repository, candidate_id="INFERRED-1", independent_evidence_count=2, transitioned_at=datetime(2026, 9, 14, tzinfo=timezone.utc))
    assert no_op.event_id == ""
    assert len(repository.nodes("CandidateStatusEvent")) == 1


def test_profile_rebuild_excludes_stale_assertions_and_marks_old_association_stale() -> None:
    from ckg.evolution.cwe_profiler import rebuild_cwe_profiles
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CWE", "CWE-611", status="CANONICAL"),
        _node("CVE", "CVE-2026-1"),
        _node("WeaknessAssertion", "W-1"),
        _node("TechniqueAssertion", "T-1"),
        _node("Technique", "TECH-OOB"),
    ], edges=[
        _edge("a", "HAS_WEAKNESS_ASSERTION", "CVE-2026-1", "W-1"),
        _edge("b", "MAPS_TO", "W-1", "CWE-611"),
        _edge("c", "HAS_TECHNIQUE_ASSERTION", "CVE-2026-1", "T-1"),
        _edge("d", "MAPS_TO", "T-1", "TECH-OOB"),
    ])
    rebuild_cwe_profiles(repository)
    repository.atomic_write(nodes=[
        _node("WeaknessAssertion", "W-1", stale=True),
    ], edges=[])

    report = rebuild_cwe_profiles(repository)

    assert report.profile_count == 0
    assert repository.nodes("ProfileAssociation")[0].props["stale"] is True
