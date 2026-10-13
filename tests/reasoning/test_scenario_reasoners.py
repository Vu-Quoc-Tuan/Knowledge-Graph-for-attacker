from datetime import datetime, timezone


def _node(label, node_id, **props):
    from ckg.graph.models import GraphNode
    return GraphNode(label=label, node_id=node_id, props=props)


def _edge(edge_id, edge_type, source, target, **props):
    from ckg.graph.models import GraphEdge
    return GraphEdge(edge_id=edge_id, edge_type=edge_type, subject_id=source, object_id=target, props=props)


def test_feedback_index_is_loaded_once_for_all_scenario_candidates() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.scenario.discoverer import _feedback_posteriors_by_scenario

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

    assert _feedback_posteriors_by_scenario(repository) == {}
    assert repository.node_reads == 2
    assert repository.edge_reads == 0


def test_scenario_materialization_writes_scenarios_and_dependencies_in_one_batch(monkeypatch) -> None:
    from ckg.application import discover_scenarios as module
    from ckg.domain.enums.scenario_type import ScenarioType
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.scenario.composer import compose

    class CountingRepository(InMemoryGraphRepository):
        def __init__(self):
            super().__init__()
            self.write_calls = 0

        def atomic_write(self, *, nodes, edges):
            self.write_calls += 1
            return super().atomic_write(nodes=nodes, edges=edges)

    repository = CountingRepository()
    repository.atomic_write(
        nodes=[
            _node("CVE", "CVE-2026-1"),
            _node("WeaknessAssertion", "W-1"),
        ],
        edges=[],
    )
    candidate = compose(
        target_vulnerability_id="CVE-2026-1",
        scenario_type=ScenarioType.NOVEL,
        weakness_ids=("CWE-89",),
        relevance=0.8,
        evidence_coverage=0.8,
        derivation_ids=("W-1",),
        premises=("test premise",),
        missing_bindings=("target_endpoint",),
    )
    monkeypatch.setattr(module, "discover_scenarios", lambda *args, **kwargs: (candidate,))
    repository.write_calls = 0

    report = module.discover_and_materialize_scenarios(repository, "CVE-2026-1")

    assert report.scenario_count == 1
    assert repository.write_calls == 1
    assert len(repository.edges("DERIVED_FROM")) == 1
    assert len(repository.edges("DEPENDS_ON")) == 1


def _span(evidence_id: str = "EVID-TEST"):
    """A source-local span, rather than an ungrounded graph relation."""
    return [{"evidence_id": evidence_id, "locator": "/advisory/body/0"}]


def _scenario_props(target, weaknesses, **extra):
    from ckg.domain.entities.scenario import Scenario
    from ckg.domain.enums.applicability import Applicability
    from ckg.domain.enums.fact_status import FactStatus
    from ckg.domain.enums.scenario_type import ScenarioType
    from ckg.domain.value_objects.confidence import Confidence

    return Scenario(scenario_id=f"SCN-{target}-{''.join(weaknesses)}", scenario_type=ScenarioType.NOVEL, status=FactStatus.VALIDATED, target_vulnerability_id=target, weakness_ids=tuple(weaknesses), applicability=Applicability.APPLICABLE, confidence=Confidence(relevance=0.8, evidence_coverage=0.8, validation=1.0, final=0.8), derivation_ids=("source",), **extra).model_dump(mode="json")


def _repository():
    from ckg.graph.memory import InMemoryGraphRepository

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001", published_at="2026-01-01T00:00:00+00:00"),
        _node("CVE", "CVE-2025-10001", published_at="2025-01-01T00:00:00+00:00"),
        _node("WeaknessAssertion", "W-TARGET"), _node("WeaknessAssertion", "W-HIST"),
        _node("CWE", "CWE-611"), _node("CWE", "CWE-918"),
        _node("Technique", "TECH-OUT_OF_BAND"), _node("CallbackChannel", "CHANNEL-DNS"), _node("Oracle", "ORACLE-EXTERNAL-INTERACTION"),
        _node("TestStrategy", "TSTRAT-XXE"),
        _node("Scenario", "SCN-HIST", **_scenario_props("CVE-2025-10001", ("CWE-611",), technique_ids=("TECH-OUT_OF_BAND",), channel_ids=("CHANNEL-DNS",), oracle_ids=("ORACLE-EXTERNAL-INTERACTION",))),
        _node("WeaknessOccurrence", "OCC-1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-611", evidence_spans=_span("EVID-OCC-1")),
        _node("WeaknessOccurrence", "OCC-2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-918", evidence_spans=_span("EVID-OCC-2")),
        _node("CompositionGroup", "GROUP-1", vulnerability_id="CVE-2026-10001", operator="ALL_OF", occurrence_ids=["OCC-1", "OCC-2"], evidence_spans=_span("EVID-GROUP-1")),
    ], edges=[
        _edge("1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10001", "W-TARGET"), _edge("2", "MAPS_TO", "W-TARGET", "CWE-611"),
        _edge("3", "HAS_WEAKNESS_ASSERTION", "CVE-2025-10001", "W-HIST"), _edge("4", "MAPS_TO", "W-HIST", "CWE-611"),
        _edge("5", "TARGETS_WEAKNESS", "TSTRAT-XXE", "CWE-611"), _edge("6", "USES_TECHNIQUE", "TSTRAT-XXE", "TECH-OUT_OF_BAND"),
        _edge("7", "USES_CHANNEL", "TSTRAT-XXE", "CHANNEL-DNS"), _edge("8", "USES_ORACLE", "TSTRAT-XXE", "ORACLE-EXTERNAL-INTERACTION"),
        _edge("9", "CAN_PRECEDE", "CWE-611", "CWE-918"), _edge("10", "ENABLES", "OCC-1", "OCC-2", evidence_spans=_span("EVID-SEQUENCE-1")),
        _edge("11", "REQUIRES", "CWE-611", "CWE-918"),
    ])
    return repository


def test_inheritance_analogy_and_test_transfer_remain_inferred_and_leave_bindings_unknown() -> None:
    from ckg.linking.historical.hybrid_retriever import retrieve_historical_neighbors
    from ckg.reasoning.analogy import analogous_scenarios
    from ckg.reasoning.context_transfer import transferable_test_strategies
    from ckg.reasoning.inheritance import inherited_scenarios
    from ckg.domain.enums.fact_status import FactStatus

    repository = _repository()
    inherited = inherited_scenarios(repository, "CVE-2026-10001")
    analogous = analogous_scenarios(repository, "CVE-2026-10001", retrieve_historical_neighbors(repository, "CVE-2026-10001"))
    transfer = transferable_test_strategies(repository, "CVE-2026-10001")

    assert len(inherited) == len(analogous) == len(transfer) == 1
    assert all(candidate.scenario.status == FactStatus.INFERRED for candidate in inherited + analogous + transfer)
    assert transfer[0].scenario.channel_ids == ("CHANNEL-DNS",)
    assert "target_endpoint" in analogous[0].missing_bindings


def test_chain_requires_both_canonical_and_instance_sequence_evidence() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.chain_reasoner import chained_scenarios

    repository = _repository()
    assert len(chained_scenarios(repository, "CVE-2026-10001")) == 1
    no_instance = InMemoryGraphRepository()
    no_instance.atomic_write(nodes=[
        _node("CWE", "CWE-611"), _node("CWE", "CWE-918"),
        _node("WeaknessOccurrence", "O1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-611"),
        _node("WeaknessOccurrence", "O2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-918"),
    ], edges=[_edge("canonical", "CAN_PRECEDE", "CWE-611", "CWE-918")])
    no_canonical = InMemoryGraphRepository()
    no_canonical.atomic_write(nodes=[
        _node("WeaknessOccurrence", "O1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-611"),
        _node("WeaknessOccurrence", "O2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-918"),
    ], edges=[_edge("instance", "ENABLES", "O1", "O2")])

    assert chained_scenarios(no_instance, "CVE-2026-10001") == ()
    assert chained_scenarios(no_canonical, "CVE-2026-10001") == ()


def test_chain_rejects_ungrounded_instance_sequence_even_with_canonical_direction() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.chain_reasoner import chained_scenarios

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CWE", "CWE-611"), _node("CWE", "CWE-918"),
        _node("WeaknessOccurrence", "O1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-611", evidence_spans=_span("EVID-O1")),
        _node("WeaknessOccurrence", "O2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-918", evidence_spans=_span("EVID-O2")),
    ], edges=[
        _edge("canonical", "CAN_PRECEDE", "CWE-611", "CWE-918"),
        _edge("instance", "ENABLES", "O1", "O2"),
    ])

    assert chained_scenarios(repository, "CVE-2026-10001") == ()


def test_chain_does_not_reverse_canonical_sequence_direction() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.chain_reasoner import chained_scenarios

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CWE", "CWE-611"),
        _node("CWE", "CWE-918"),
        _node("WeaknessOccurrence", "O1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-611", evidence_spans=_span("EVID-O1")),
        _node("WeaknessOccurrence", "O2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-918", evidence_spans=_span("EVID-O2")),
    ], edges=[
        _edge("canonical", "CAN_PRECEDE", "CWE-918", "CWE-611"),
        _edge("instance", "ENABLES", "O1", "O2", evidence_spans=_span("EVID-SEQUENCE")),
    ])

    assert chained_scenarios(repository, "CVE-2026-10001") == ()


def test_composite_requires_explicit_all_of_group_not_merely_two_occurrences() -> None:
    from ckg.reasoning.composite_reasoner import composite_scenarios

    repository = _repository()
    composite = composite_scenarios(repository, "CVE-2026-10001")

    assert len(composite) == 1
    assert composite[0].scenario.weakness_ids == ("CWE-611", "CWE-918")
    assert composite[0].premises == ("explicit ALL_OF occurrence composition",)


def test_composite_can_use_direct_instance_composition_with_canonical_requires() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.composite_reasoner import composite_scenarios

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CWE", "CWE-611"),
        _node("CWE", "CWE-918"),
        _node("WeaknessOccurrence", "O1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-611", evidence_spans=_span("EVID-O1")),
        _node("WeaknessOccurrence", "O2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-918", evidence_spans=_span("EVID-O2")),
    ], edges=[
        _edge("canonical", "REQUIRES", "CWE-611", "CWE-918"),
        _edge("instance", "REQUIRED_TOGETHER", "O1", "O2", evidence_spans=_span("EVID-ALL-OF")),
    ])

    result = composite_scenarios(repository, "CVE-2026-10001")
    assert len(result) == 1
    assert result[0].premises == (
        "canonical composite relation",
        "instance required-together relation",
    )


def test_composite_rejects_ungrounded_all_of_group() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.composite_reasoner import composite_scenarios

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("WeaknessOccurrence", "O1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-611", evidence_spans=_span("EVID-O1")),
        _node("WeaknessOccurrence", "O2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-918", evidence_spans=_span("EVID-O2")),
        _node("CompositionGroup", "GROUP", vulnerability_id="CVE-2026-10001", operator="ALL_OF", occurrence_ids=["O1", "O2"]),
    ], edges=[])

    assert composite_scenarios(repository, "CVE-2026-10001") == ()


def test_discovery_applies_constraint_before_ranking_and_never_materializes_bindings() -> None:
    from ckg.application.discover_scenarios import discover_and_materialize_scenarios
    from ckg.constraints.evaluator import EnvironmentSnapshot

    repository = _repository()
    repository.atomic_write(nodes=[
        _node("ApplicabilityConstraint", "CONSTRAINT-DNS", expression='{"kind":"network","key":"dns_egress","equals":true}'),
        _node("Scenario", "SCN-HIST-CONSTRAINED", **_scenario_props("CVE-2025-10001", ("CWE-611",), constraint_ids=("CONSTRAINT-DNS",))),
    ], edges=[])

    report = discover_and_materialize_scenarios(repository, "CVE-2026-10001", environment=EnvironmentSnapshot(environment_id="ENV", network={"dns_egress": False}))
    scenarios = repository.nodes("Scenario")
    discovered = [node for node in scenarios if node.node_id in report.scenario_ids]

    assert report.scenario_count >= 1
    assert any(node.props["applicability"] == "NOT_APPLICABLE" for node in discovered)
    assert all("target.local" not in str(node.props) and "callback_url" not in str(node.props) for node in discovered)


def test_composite_rejects_empty_span_dict() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.composite_reasoner import composite_scenarios

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CWE", "CWE-611"),
        _node("CWE", "CWE-918"),
        _node("WeaknessOccurrence", "O1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-611", evidence_spans=[{}]),
        _node("WeaknessOccurrence", "O2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-918", evidence_spans=[{}]),
        _node("CompositionGroup", "GROUP", vulnerability_id="CVE-2026-10001", operator="ALL_OF", occurrence_ids=["O1", "O2"], evidence_spans=[{}]),
    ], edges=[
        _edge("canonical", "REQUIRES", "CWE-611", "CWE-918"),
    ])

    assert composite_scenarios(repository, "CVE-2026-10001") == ()


def test_composite_rejects_all_of_without_canonical_requires() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.composite_reasoner import composite_scenarios

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CWE", "CWE-611"),
        _node("CWE", "CWE-918"),
        _node("WeaknessOccurrence", "O1", vulnerability_id="CVE-2026-10001", cwe_id="CWE-611", evidence_spans=_span("EVID-O1")),
        _node("WeaknessOccurrence", "O2", vulnerability_id="CVE-2026-10001", cwe_id="CWE-918", evidence_spans=_span("EVID-O2")),
        _node("CompositionGroup", "GROUP", vulnerability_id="CVE-2026-10001", operator="ALL_OF", occurrence_ids=["O1", "O2"], evidence_spans=_span("EVID-GROUP")),
    ], edges=[])  # No canonical REQUIRES edge

    assert composite_scenarios(repository, "CVE-2026-10001") == ()


def test_chained_scenarios_opposite_directions_have_distinct_ids() -> None:
    from ckg.domain.enums.scenario_type import ScenarioType
    from ckg.scenario.composer import compose

    c1 = compose(
        target_vulnerability_id="CVE-2026-10001",
        scenario_type=ScenarioType.CHAINED,
        weakness_ids=("CWE-611", "CWE-918"),
        relevance=0.8,
        evidence_coverage=0.7,
        derivation_ids=("O1", "O2", "E1"),
        premises=("p1",),
    )
    c2 = compose(
        target_vulnerability_id="CVE-2026-10001",
        scenario_type=ScenarioType.CHAINED,
        weakness_ids=("CWE-918", "CWE-611"),
        relevance=0.8,
        evidence_coverage=0.7,
        derivation_ids=("O2", "O1", "E2"),
        premises=("p1",),
    )

    assert c1.scenario.scenario_id != c2.scenario.scenario_id
    assert c1.scenario.weakness_ids == ("CWE-611", "CWE-918")
    assert c2.scenario.weakness_ids == ("CWE-918", "CWE-611")


def test_analogy_rejects_dimension_conflict_even_with_shared_facet() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.linking.historical.hybrid_retriever import HistoricalNeighbor
    from ckg.reasoning.analogy import analogous_scenarios

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10002"),
        _node("WeaknessAssertion", "W-TARGET"),
        _node("CWE", "CWE-611"),
        _node("ContextAssertion", "CTX-T1"),
        _node("ContextAssertion", "CTX-T2"),
        _node("DataFormat", "FORMAT-XML"),
        _node("Language", "LANG-PYTHON"),

        _node("CVE", "CVE-2025-10002"),
        _node("WeaknessAssertion", "W-NEIGHBOR"),
        _node("ContextAssertion", "CTX-N1"),
        _node("ContextAssertion", "CTX-N2"),
        _node("Language", "LANG-PHP"),
        _node("Scenario", "SCN-NEIGHBOR", **_scenario_props("CVE-2025-10002", ("CWE-611",), context_ids=("FORMAT-XML", "LANG-PHP"))),
    ], edges=[
        _edge("1", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10002", "W-TARGET"),
        _edge("2", "MAPS_TO", "W-TARGET", "CWE-611"),
        _edge("3", "HAS_CONTEXT_ASSERTION", "CVE-2026-10002", "CTX-T1"),
        _edge("4", "MAPS_TO", "CTX-T1", "FORMAT-XML"),
        _edge("5", "HAS_CONTEXT_ASSERTION", "CVE-2026-10002", "CTX-T2"),
        _edge("6", "MAPS_TO", "CTX-T2", "LANG-PYTHON"),

        _edge("7", "HAS_WEAKNESS_ASSERTION", "CVE-2025-10002", "W-NEIGHBOR"),
        _edge("8", "MAPS_TO", "W-NEIGHBOR", "CWE-611"),
        _edge("9", "HAS_CONTEXT_ASSERTION", "CVE-2025-10002", "CTX-N1"),
        _edge("10", "MAPS_TO", "CTX-N1", "FORMAT-XML"),
        _edge("11", "HAS_CONTEXT_ASSERTION", "CVE-2025-10002", "CTX-N2"),
        _edge("12", "MAPS_TO", "CTX-N2", "LANG-PHP"),
    ])

    neighbor = HistoricalNeighbor("CVE-2025-10002", 0.9, frozenset({"same_weakness", "same_context"}))
    analogous = analogous_scenarios(repository, "CVE-2026-10002", (neighbor,))

    # Must be rejected due to LANG-PYTHON vs LANG-PHP conflict even though FORMAT-XML is shared!
    assert analogous == ()
