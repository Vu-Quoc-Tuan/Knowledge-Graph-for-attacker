"""Compose independent reasoner outputs and apply environment constraints before ranking."""

from __future__ import annotations

from ckg.constraints.evaluator import EnvironmentSnapshot, evaluate
from ckg.domain.enums.applicability import Applicability
from ckg.graph.ports import GraphRepository
from ckg.linking.historical.hybrid_retriever import retrieve_historical_neighbors
from ckg.reasoning.analogy import analogous_scenarios
from ckg.reasoning.chain_reasoner import chained_scenarios
from ckg.reasoning.composite_reasoner import composite_scenarios
from ckg.reasoning.context_transfer import transferable_test_strategies
from ckg.reasoning.inheritance import inherited_scenarios
from ckg.reasoning.subgraph.builder import LocalSubgraph, build_local_subgraph, _visible
from ckg.reasoning.subgraph.repository import LocalSubgraphRepository
from ckg.scenario.contract import ScenarioCandidate
from ckg.scenario.deduplicator import deduplicate
from ckg.scenario.ranker import rank
from ckg.scenario.synthesizer import synthesized_scenarios


from datetime import datetime
from ckg.reasoning.subgraph.pruning import evidence_closure


def _apply_constraints(repository: GraphRepository, candidate: ScenarioCandidate, environment: EnvironmentSnapshot | None) -> ScenarioCandidate:
    if environment is None or not candidate.scenario.constraint_ids:
        return candidate
    constraints = {node.node_id: node for node in repository.nodes("ApplicabilityConstraint")}
    missing = [item for item in candidate.scenario.constraint_ids if item not in constraints or "expression" not in constraints[item].props]
    results = [
        evaluate(constraints[item].props["expression"], environment).applicability
        for item in candidate.scenario.constraint_ids
        if item in constraints and "expression" in constraints[item].props
    ]
    if missing or not results:
        applicability = Applicability.UNKNOWN
    elif any(result == Applicability.NOT_APPLICABLE for result in results):
        applicability = Applicability.NOT_APPLICABLE
    elif any(result == Applicability.UNKNOWN for result in results):
        applicability = Applicability.UNKNOWN
    else:
        applicability = Applicability.APPLICABLE
    return candidate.model_copy(update={"scenario": candidate.scenario.model_copy(update={"applicability": applicability})})


def _feedback_posteriors_by_scenario(
    repository: GraphRepository, as_of: datetime | None = None
) -> dict[str, tuple[GraphNode, ...]]:
    """Build the execution-feedback index once for a discovery run."""
    revisions = [node for node in repository.nodes("ScopedBeliefPosteriorRevision") if _visible(node, as_of)]
    if revisions:
        selected: dict[str, GraphNode] = {}
        for node in revisions:
            posterior_id = str(node.props.get("posterior_id", ""))
            current = selected.get(posterior_id)
            if current is None or str(node.props.get("observed_at", "")) > str(current.props.get("observed_at", "")):
                selected[posterior_id] = node
        all_posteriors = selected
    else:
        all_posteriors = {
            node.node_id: node
            for node in repository.nodes("ScopedBeliefPosterior")
            if _visible(node, as_of)
        }
    if not all_posteriors:
        return {}

    updates_by_execution: dict[str, list[GraphNode]] = {}
    for edge in repository.edges("UPDATES_BELIEF"):
        posterior = all_posteriors.get(edge.object_id)
        if posterior is not None:
            updates_by_execution.setdefault(edge.subject_id, []).append(posterior)
    by_scenario: dict[str, list[GraphNode]] = {}
    for edge in repository.edges("EXECUTED_AS"):
        by_scenario.setdefault(edge.object_id, []).extend(
            updates_by_execution.get(edge.subject_id, ())
        )
    return {
        scenario_id: tuple(posteriors)
        for scenario_id, posteriors in by_scenario.items()
    }


def _apply_feedback_index(
    candidate: ScenarioCandidate,
    posteriors_by_scenario: dict[str, tuple[GraphNode, ...]],
) -> ScenarioCandidate:
    scenario_id = candidate.scenario.scenario_id
    posteriors = posteriors_by_scenario.get(scenario_id, ())
    # A bucket keyed only by CWE (or an arbitrary caller string) is not a
    # compatible execution environment.  Until a candidate carries an exact
    # immutable environment-scope ID, feedback is allowed to affect only the
    # scenario that was actually executed.
    if posteriors:
        avg_mean = sum(float(p.props.get("mean", 0.5)) for p in posteriors) / len(posteriors)
        curr_conf = candidate.scenario.confidence
        new_support = avg_mean
        new_final = min(curr_conf.relevance, curr_conf.evidence_coverage) * (0.5 + 0.5 * avg_mean)
        updated_conf = curr_conf.model_copy(update={"historical_support": new_support, "final": new_final})
        return candidate.model_copy(update={"scenario": candidate.scenario.model_copy(update={"confidence": updated_conf})})
    return candidate


def _apply_feedback_posteriors(
    repository: GraphRepository,
    candidate: ScenarioCandidate,
    as_of: datetime | None = None,
) -> ScenarioCandidate:
    """Compatibility entry point for applying feedback to one candidate."""
    return _apply_feedback_index(
        candidate,
        _feedback_posteriors_by_scenario(repository, as_of=as_of),
    )


def _merge_local_subgraphs(
    root: LocalSubgraph, historical: tuple[LocalSubgraph, ...], *, hard_max_nodes: int
) -> LocalSubgraph:
    """Merge deterministic local envelopes while retaining one global cap and evidence closure."""

    nodes = {node.node_id: node for node in root.nodes}
    edges = {edge.edge_id: edge for edge in root.edges}
    dropped = set(root.dropped_node_ids)
    temporal_excluded = set(root.temporal_excluded_node_ids)
    truncated = root.truncated
    for graph in historical:
        temporal_excluded.update(graph.temporal_excluded_node_ids)
        for node in graph.nodes:
            if node.node_id in nodes:
                continue
            if len(nodes) >= hard_max_nodes:
                dropped.add(node.node_id)
                truncated = True
                continue
            nodes[node.node_id] = node
        for edge in graph.edges:
            if edge.subject_id in nodes and edge.object_id in nodes:
                edges[edge.edge_id] = edge
    selected_nodes = list(nodes.values())
    selected_edges = list(edges.values())
    selected_nodes, selected_edges = evidence_closure(selected_nodes, selected_edges)
    return LocalSubgraph(
        root.root_id,
        tuple(sorted(selected_nodes, key=lambda node: node.node_id)),
        tuple(sorted(selected_edges, key=lambda edge: edge.edge_id)),
        truncated,
        tuple(sorted(dropped)),
        tuple(sorted(temporal_excluded)),
    )


def discover_scenarios(repository: GraphRepository, vulnerability_id: str, *, environment: EnvironmentSnapshot | None = None, historical_top_k: int = 5, as_of: datetime | None = None) -> tuple[ScenarioCandidate, ...]:
    # Retrieval is the one deliberately global operation. All downstream
    # reasoners receive a read-only, bounded projection, never ``repository``.
    root_graph = build_local_subgraph(repository, vulnerability_id, as_of=as_of)
    neighbors = retrieve_historical_neighbors(repository, vulnerability_id, top_k=historical_top_k, as_of=as_of)
    historical_graphs = tuple(
        build_local_subgraph(repository, neighbor.vulnerability_id, as_of=as_of)
        for neighbor in neighbors
    )
    local_graph = _merge_local_subgraphs(
        root_graph, historical_graphs, hard_max_nodes=200
    )
    local_repository = LocalSubgraphRepository(local_graph)
    visible_ids = {node.node_id for node in local_graph.nodes}
    neighbors = tuple(neighbor for neighbor in neighbors if neighbor.vulnerability_id in visible_ids)
    candidates = (
        synthesized_scenarios(local_repository, vulnerability_id, neighbors, as_of=as_of)
        + inherited_scenarios(local_repository, vulnerability_id)
        + analogous_scenarios(local_repository, vulnerability_id, neighbors)
        + transferable_test_strategies(local_repository, vulnerability_id)
        + chained_scenarios(local_repository, vulnerability_id)
        + composite_scenarios(local_repository, vulnerability_id)
    )
    evaluated = tuple(_apply_constraints(local_repository, candidate, environment) for candidate in candidates)
    feedback = _feedback_posteriors_by_scenario(repository, as_of=as_of)
    evaluated = tuple(
        _apply_feedback_index(candidate, feedback) for candidate in evaluated
    )
    return rank(deduplicate(evaluated))
