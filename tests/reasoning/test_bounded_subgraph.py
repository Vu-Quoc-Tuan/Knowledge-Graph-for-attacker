from datetime import datetime, timezone


def _node(label, node_id, **props):
    from ckg.graph.models import GraphNode
    return GraphNode(label=label, node_id=node_id, props=props)


def _edge(edge_id, edge_type, source, target, **props):
    from ckg.graph.models import GraphEdge
    return GraphEdge(
        edge_id=edge_id, edge_type=edge_type,
        subject_id=source, object_id=target, props=props,
    )


def test_local_subgraph_is_whitelisted_bounded_and_keeps_assertion_evidence_closure() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.subgraph.builder import build_local_subgraph
    from ckg.reasoning.subgraph.budgets import SubgraphBudget

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001", published_at="2026-01-01T00:00:00+00:00"),
        _node("WeaknessAssertion", "WAS-1", provenance={"retrieved_at": "2026-01-02T00:00:00+00:00"}, evidence_spans=[{"evidence_id": "EVID-1"}]),
        _node("Evidence", "EVID-1", retrieved_at="2026-01-02T00:00:00+00:00"),
        _node("CWE", "CWE-611"), _node("CWE", "CWE-1"), _node("CWE", "CWE-2"), _node("CWE", "CWE-3"),
        _node("CVE", "CVE-2025-20001", published_at="2025-01-01T00:00:00+00:00"),
        _node("Evidence", "EVID-LATE", retrieved_at="2027-01-01T00:00:00+00:00"),
    ], edges=[
        _edge("a", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10001", "WAS-1"),
        _edge("b", "MAPS_TO", "WAS-1", "CWE-611"),
        _edge("c", "SUPPORTED_BY", "CVE-2026-10001", "EVID-1"),
        _edge("d", "PEER_OF", "CWE-611", "CWE-1"),
        _edge("e", "PEER_OF", "CWE-611", "CWE-2"),
        _edge("f", "PEER_OF", "CWE-611", "CWE-3"),
        _edge("g", "SIMILAR_TO", "CVE-2026-10001", "CVE-2025-20001"),
        _edge("h", "UNSAFE_NOT_WHITELISTED", "CVE-2026-10001", "EVID-LATE"),
    ])

    result = build_local_subgraph(repository, "CVE-2026-10001", budget=SubgraphBudget(cwe=2, evidence=2, historical_cves=1, max_depth=3), as_of=datetime(2026, 9, 14, tzinfo=timezone.utc))

    node_ids = {node.node_id for node in result.nodes}
    assert {"CVE-2026-10001", "WAS-1", "EVID-1", "CWE-611", "CVE-2025-20001"} <= node_ids
    assert "EVID-LATE" not in node_ids
    assert "WAS-1" in node_ids  # it retains its referenced Evidence node
    assert len({node.node_id for node in result.nodes if node.label == "CWE"}) <= 2
    assert all(edge.edge_type != "UNSAFE_NOT_WHITELISTED" for edge in result.edges)
    assert result.truncated is True


def test_missing_assertion_evidence_does_not_leave_detached_weakness_context() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.subgraph.builder import build_local_subgraph

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001"),
        _node("WeaknessAssertion", "WAS-1", evidence_spans=[{"evidence_id": "EVID-MISSING"}], all_source_snapshots_available=False),
        _node("CWE", "CWE-89"),
        _node("PayloadFamily", "FAMILY-1", slice_cwe_id="CWE-89"),
    ], edges=[
        _edge("a", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10001", "WAS-1"),
        _edge("b", "MAPS_TO", "WAS-1", "CWE-89"),
        _edge("c", "HAS_PAYLOAD_FAMILY", "CWE-89", "FAMILY-1"),
    ])

    result = build_local_subgraph(repository, "CVE-2026-10001")
    assert {node.node_id for node in result.nodes} == {"CVE-2026-10001"}
    assert result.edges == ()


def test_as_of_does_not_silently_include_undated_noncanonical_nodes() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.subgraph.builder import build_local_subgraph

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001", published_at="2026-01-01T00:00:00+00:00"),
        _node("TechniqueAssertion", "TAS-UNDATED"),
        _node("Technique", "TECH-OUT_OF_BAND"),
    ], edges=[
        _edge("a", "HAS_TECHNIQUE_ASSERTION", "CVE-2026-10001", "TAS-UNDATED"),
        _edge("b", "MAPS_TO", "TAS-UNDATED", "TECH-OUT_OF_BAND"),
    ])

    result = build_local_subgraph(repository, "CVE-2026-10001", as_of=datetime(2026, 9, 14, tzinfo=timezone.utc))

    assert {node.node_id for node in result.nodes} == {"CVE-2026-10001"}
    assert result.temporal_excluded_node_ids == ("TAS-UNDATED",)


def test_as_of_does_not_treat_undated_wstg_or_patt_as_timeless_ontology() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.subgraph.builder import build_local_subgraph

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001", published_at="2026-01-01T00:00:00+00:00"),
        _node("WSTGCase", "WSTG-UNDATED"),
        _node("PATTSection", "PATT-UNDATED"),
    ], edges=[
        _edge("a", "DESCRIBES", "CVE-2026-10001", "WSTG-UNDATED"),
        _edge("b", "DERIVED_FROM", "CVE-2026-10001", "PATT-UNDATED"),
    ])

    result = build_local_subgraph(
        repository,
        "CVE-2026-10001",
        as_of=datetime(2026, 9, 14, tzinfo=timezone.utc),
    )

    assert {node.node_id for node in result.nodes} == {"CVE-2026-10001"}
    assert result.temporal_excluded_node_ids == ("PATT-UNDATED", "WSTG-UNDATED")


def test_current_subgraph_uses_compact_patt_family_and_technology_context() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.subgraph.builder import build_local_subgraph

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CWE", "CWE-79"),
        _node("PayloadFamily", "PATT-FAMILY-XSS", family_key="xss.generic", name="Cross-site scripting", slice_cwe_id="CWE-79", technologies=["PHP"]),
        _node("Technology", "PATT-TECH-PHP", name="PHP"),
    ], edges=[
        _edge("family", "HAS_PAYLOAD_FAMILY", "CWE-79", "PATT-FAMILY-XSS"),
        _edge("technology", "APPLIES_TO", "PATT-FAMILY-XSS", "PATT-TECH-PHP"),
    ])

    current = build_local_subgraph(repository, "CWE-79")
    historical = build_local_subgraph(
        repository,
        "CWE-79",
        as_of=datetime(2026, 9, 14, tzinfo=timezone.utc),
    )

    assert {node.node_id for node in current.nodes} == {
        "CWE-79", "PATT-FAMILY-XSS", "PATT-TECH-PHP",
    }
    assert {edge.edge_type for edge in current.edges} == {"HAS_PAYLOAD_FAMILY", "APPLIES_TO"}
    assert {node.node_id for node in historical.nodes} == {"CWE-79"}


def test_cve_subgraph_anchors_patt_context_beyond_general_depth_limit() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.subgraph.builder import build_local_subgraph
    from ckg.reasoning.subgraph.budgets import SubgraphBudget

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10101", published_at="2026-01-01T00:00:00+00:00"),
        _node("WeaknessAssertion", "WAS-101", evidence_spans=[]),
        _node("CWE", "CWE-89"),
        _node("CWE", "CWE-78"),
        _node(
            "PayloadFamily", "PATT-SQLI-UNION", family_key="sqli.union",
            name="UNION-based", slice_cwe_id="CWE-89", technologies=["PostgreSQL"],
        ),
        _node(
            "PayloadFamily", "PATT-CMDI", family_key="cmdi.generic",
            name="OS command injection", slice_cwe_id="CWE-78", technologies=["Linux"],
        ),
        _node("Technology", "PATT-TECH-POSTGRESQL", name="PostgreSQL"),
        _node("Technology", "PATT-TECH-LINUX", name="Linux"),
    ], edges=[
        _edge("assertion", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10101", "WAS-101"),
        _edge("maps", "MAPS_TO", "WAS-101", "CWE-89"),
        _edge("neighbor", "PEER_OF", "CWE-89", "CWE-78"),
        _edge("family", "HAS_PAYLOAD_FAMILY", "CWE-89", "PATT-SQLI-UNION"),
        _edge("technology", "APPLIES_TO", "PATT-SQLI-UNION", "PATT-TECH-POSTGRESQL"),
        _edge("neighbor-family", "HAS_PAYLOAD_FAMILY", "CWE-78", "PATT-CMDI"),
        _edge("neighbor-technology", "APPLIES_TO", "PATT-CMDI", "PATT-TECH-LINUX"),
    ])

    result = build_local_subgraph(
        repository,
        "CVE-2026-10101",
        budget=SubgraphBudget(max_depth=2),
    )

    node_ids = {node.node_id for node in result.nodes}
    assert {"CVE-2026-10101", "CWE-89", "PATT-SQLI-UNION", "PATT-TECH-POSTGRESQL"} <= node_ids
    assert "PATT-CMDI" not in node_ids
    assert "PATT-TECH-LINUX" not in node_ids
    assert {"HAS_PAYLOAD_FAMILY", "APPLIES_TO"} <= {edge.edge_type for edge in result.edges}


def test_local_subgraph_uses_storage_bounded_neighborhood_when_available() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import BoundedNeighborhood
    from ckg.reasoning.subgraph.builder import build_local_subgraph

    class BoundedRepository(InMemoryGraphRepository):
        invoked = False

        def bounded_neighborhood(self, *args, **kwargs):
            self.invoked = True
            return BoundedNeighborhood(tuple(self.nodes()), tuple(self.edges()), truncated=True)

    repository = BoundedRepository()
    repository.atomic_write(nodes=[_node("CVE", "CVE-2026-10001", published_at="2026-01-01T00:00:00+00:00")], edges=[])

    result = build_local_subgraph(repository, "CVE-2026-10001")

    assert repository.invoked is True
    assert result.truncated is True


def test_production_bounded_subgraph_never_exports_global_nodes_or_edges() -> None:
    """A production adapter may offer only bounded/query-specific reads.

    This catches accidental fallback to ``nodes()`` / ``edges()`` after a
    database has already supplied its capped neighbourhood.
    """
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import BoundedNeighborhood
    from ckg.reasoning.subgraph.builder import build_local_subgraph

    class ProductionLikeRepository(InMemoryGraphRepository):
        def bounded_neighborhood(self, *args, **kwargs):
            return BoundedNeighborhood(tuple(self._nodes.values()), tuple(self._edges.values()))

        def nodes(self, label=None):  # pragma: no cover - must never be reached
            raise AssertionError("global node export escaped the bounded DB query")

        def edges(self, edge_type=None):  # pragma: no cover - must never be reached
            raise AssertionError("global edge export escaped the bounded DB query")

        def find_nodes(self, label, properties):
            return sorted(
                (node for node in self._nodes.values() if node.label == label and all(node.props.get(key) == value for key, value in properties.items())),
                key=lambda node: node.node_id,
            )

        def nodes_by_ids(self, node_ids):
            return sorted((node for node_id, node in self._nodes.items() if node_id in node_ids), key=lambda node: node.node_id)

        def edges_between(self, node_ids, *, edge_types=None):
            return sorted(
                (edge for edge in self._edges.values() if edge.subject_id in node_ids and edge.object_id in node_ids and (edge_types is None or edge.edge_type in edge_types)),
                key=lambda edge: edge.edge_id,
            )

    repository = ProductionLikeRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001", published_at="2026-01-01T00:00:00+00:00"),
        _node("WeaknessAssertion", "WAS-1", evidence_spans=[]),
        _node("CWE", "CWE-611"),
    ], edges=[
        _edge("has", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10001", "WAS-1"),
        _edge("maps", "MAPS_TO", "WAS-1", "CWE-611"),
    ])

    result = build_local_subgraph(repository, "CVE-2026-10001")

    assert {node.node_id for node in result.nodes} == {"CVE-2026-10001", "WAS-1", "CWE-611"}


def test_as_of_excludes_late_edge_between_old_visible_nodes() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.subgraph.builder import build_local_subgraph

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        _node("CVE", "CVE-2026-10001", published_at="2026-01-01T00:00:00+00:00"),
        _node("WeaknessAssertion", "WAS-1", retrieved_at="2026-01-02T00:00:00+00:00"),
    ], edges=[
        _edge("late", "HAS_WEAKNESS_ASSERTION", "CVE-2026-10001", "WAS-1"),
    ])
    # A source relation can be discovered after both endpoints existed. Its
    # availability date, not endpoint publication dates, controls the split.
    late = repository.edges()[0]
    repository.atomic_write(nodes=[], edges=[
        late.model_copy(update={"props": {"retrieved_at": "2027-01-01T00:00:00+00:00"}})
    ])

    result = build_local_subgraph(
        repository,
        "CVE-2026-10001",
        as_of=datetime(2026, 9, 14, tzinfo=timezone.utc),
    )

    assert {node.node_id for node in result.nodes} == {"CVE-2026-10001"}


def test_future_cwe_import_does_not_break_past_as_of_query() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.reasoning.subgraph.builder import build_local_subgraph

    repository = InMemoryGraphRepository()
    # Release A in January 2026
    repository.atomic_write(nodes=[
        _node("CWE", "CWE-79", name="XSS v1", first_seen_at="2026-01-15T00:00:00+00:00", retrieved_at="2026-01-15T00:00:00+00:00"),
        _node("CWEContentRevision", "CWE-CONTENT-CWE-79-4.18", canonical_id="CWE-79", source_release="4.18", name="XSS v1", retrieved_at="2026-01-15T00:00:00+00:00"),
    ], edges=[])

    # Query in February 2026
    feb = datetime(2026, 2, 1, tzinfo=timezone.utc)
    res1 = build_local_subgraph(repository, "CWE-79", as_of=feb)
    assert any(n.node_id == "CWE-79" and n.props.get("name") == "XSS v1" for n in res1.nodes)

    # Release B in March 2026 arrives (future data)
    repository.atomic_write(nodes=[
        _node("CWE", "CWE-79", name="XSS v2", first_seen_at="2026-01-15T00:00:00+00:00", retrieved_at="2026-03-15T00:00:00+00:00"),
        _node("CWEContentRevision", "CWE-CONTENT-CWE-79-4.19", canonical_id="CWE-79", source_release="4.19", name="XSS v2", retrieved_at="2026-03-15T00:00:00+00:00"),
    ], edges=[])

    # Re-query in February 2026 must still succeed and reflect v1!
    res2 = build_local_subgraph(repository, "CWE-79", as_of=feb)
    cwe_node = next(n for n in res2.nodes if n.node_id == "CWE-79")
    assert cwe_node.props.get("name") == "XSS v1"


def test_current_catalog_view_excludes_relation_removed_by_later_release() -> None:
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphEdge, GraphNode
    from ckg.reasoning.subgraph.builder import build_local_subgraph

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="CWE", node_id="CWE-79", props={}),
        GraphNode(label="CWE", node_id="CWE-20", props={}),
        GraphNode(label="CWEContentRevision", node_id="R79-18", props={"canonical_id": "CWE-79", "source_release": "4.18", "retrieved_at": "2026-01-01T00:00:00+00:00"}),
        GraphNode(label="CWEContentRevision", node_id="R20-18", props={"canonical_id": "CWE-20", "source_release": "4.18", "retrieved_at": "2026-01-01T00:00:00+00:00"}),
        GraphNode(label="CWEContentRevision", node_id="R79-19", props={"canonical_id": "CWE-79", "source_release": "4.19", "retrieved_at": "2026-03-01T00:00:00+00:00"}),
        GraphNode(label="CWEContentRevision", node_id="R20-19", props={"canonical_id": "CWE-20", "source_release": "4.19", "retrieved_at": "2026-03-01T00:00:00+00:00"}),
    ], edges=[
        GraphEdge(edge_id="old-child", edge_type="CHILD_OF", subject_id="CWE-79", object_id="CWE-20", props={"source_release": "4.18", "retrieved_at": "2026-01-01T00:00:00+00:00"}),
    ])

    february = build_local_subgraph(repository, "CWE-79", as_of=datetime(2026, 2, 1, tzinfo=timezone.utc))
    april = build_local_subgraph(repository, "CWE-79", as_of=datetime(2026, 4, 1, tzinfo=timezone.utc))
    assert {node.node_id for node in february.nodes} >= {"CWE-79", "CWE-20"}
    assert {node.node_id for node in april.nodes} == {"CWE-79"}
