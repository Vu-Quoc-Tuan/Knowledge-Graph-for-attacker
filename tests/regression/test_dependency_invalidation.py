from datetime import datetime, timezone


def test_evidence_invalidation_marks_dependents_stale_without_deleting_history() -> None:
    from ckg.evolution.dependencies import invalidate_dependents, record_dependency
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="Evidence", node_id="EVID-1", props={"evidence_id": "EVID-1"}),
        GraphNode(label="WeaknessAssertion", node_id="WAS-1", props={"assertion_id": "WAS-1"}),
        GraphNode(label="Scenario", node_id="SCN-1", props={"scenario_id": "SCN-1"}),
    ], edges=[])
    record_dependency(repository, dependent_id="WAS-1", source_id="EVID-1")
    record_dependency(repository, dependent_id="SCN-1", source_id="WAS-1")

    report = invalidate_dependents(repository, source_id="EVID-1", reason="snapshot superseded", occurred_at=datetime(2026, 9, 14, tzinfo=timezone.utc))

    assert report.invalidated_ids == ("SCN-1", "WAS-1")
    assert {node.node_id for node in repository.nodes()} >= {"EVID-1", "WAS-1", "SCN-1"}
    assert len(repository.nodes("InvalidationEvent")) == 2
    assert all(node.props["stale"] is True for node in (repository.nodes("WeaknessAssertion") + repository.nodes("Scenario")))
