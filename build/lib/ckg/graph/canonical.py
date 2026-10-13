"""Read immutable canonical content without mutating stable ontology IDs."""

from __future__ import annotations

from datetime import datetime, timezone

from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def canonical_content_by_id(
    repository: GraphRepository, catalog: str, *, as_of: datetime | None = None
) -> dict[str, GraphNode]:
    """Return one immutable content revision per stable canonical identifier.

    A source release can arrive after an earlier release has already seeded
    the graph.  Selecting by content revision prevents that later import from
    rewriting the historical definition attached to the stable ``:CWE`` or
    ``:CAPEC`` identity node.  Undated revisions are deliberately excluded
    from an as-of projection.
    """
    selected: dict[str, tuple[datetime, str, GraphNode]] = {}
    for node in repository.canonical_content_revisions(catalog):
        canonical_id = node.props.get("canonical_id")
        timestamp = _timestamp(node.props.get("retrieved_at"))
        if not isinstance(canonical_id, str) or timestamp is None:
            continue
        # Historical source files may contain naive timestamps. Treat them as
        # UTC so mixed source timestamps remain comparable.
        timestamp = timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp.astimezone(timezone.utc)
        if as_of is not None:
            cutoff = as_of.replace(tzinfo=timezone.utc) if as_of.tzinfo is None else as_of.astimezone(timezone.utc)
            if timestamp > cutoff:
                continue
        candidate = (timestamp, node.node_id, node)
        existing = selected.get(canonical_id)
        if existing is None or candidate[:2] > existing[:2]:
            selected[canonical_id] = candidate
    return {canonical_id: item[2] for canonical_id, item in selected.items()}


def canonical_edge_visible(
    repository: GraphRepository,
    edge: GraphEdge,
    *,
    as_of: datetime | None = None,
    cwe_content: dict[str, GraphNode] | None = None,
    capec_content: dict[str, GraphNode] | None = None,
) -> bool:
    """Keep historical catalog edges auditable but out of an effective view.

    A release-scoped CWE hierarchy/member edge is usable only while it agrees
    with the selected CWE content revisions.  CAPEC relations are scoped by
    their CAPEC subject release; their CWE target may legitimately be from a
    differently-versioned catalog.
    """
    source_release = edge.props.get("source_release")
    if not isinstance(source_release, str):
        return True
    # Catalog relations originate at a stable CAPEC, CWE, category, or view
    # identity. A missing selected revision must not make such an edge visible.
    capec_subject = edge.subject_id.startswith("CAPEC-") and edge.subject_id[6:].isdigit()
    cwe_subject = edge.subject_id.startswith("CWE-") and edge.subject_id[4:].isdigit()
    group_subject = edge.subject_id.startswith(("CWE-CATEGORY-", "CWE-VIEW-"))
    cwe = cwe_content if cwe_content is not None else canonical_content_by_id(repository, "CWE", as_of=as_of)
    capec = capec_content if capec_content is not None else canonical_content_by_id(repository, "CAPEC", as_of=as_of)
    if capec_subject:
        revision = capec.get(edge.subject_id)
        return revision is not None and revision.props.get("source_release") == source_release
    if edge.edge_type == "HAS_CANONICAL_REVISION":
        if edge.object_id.startswith("CAPEC-") and edge.object_id[6:].isdigit():
            revision = capec.get(edge.object_id)
            return revision is not None and revision.props.get("source_release") == source_release
        if edge.object_id.startswith("CWE-") and edge.object_id[4:].isdigit():
            revision = cwe.get(edge.object_id)
            return revision is not None and revision.props.get("source_release") == source_release
    cwe_endpoints = [
        identifier for identifier in (edge.subject_id, edge.object_id)
        if identifier.startswith("CWE-") and identifier[4:].isdigit()
    ]
    if cwe_subject or group_subject:
        return bool(cwe_endpoints) and all(
            (revision := cwe.get(identifier)) is not None
            and revision.props.get("source_release") == source_release
            for identifier in cwe_endpoints
        )
    # Other edge types retain the previous behavior: only already-selected
    # CWE content can constrain them.
    selected_endpoints = [identifier for identifier in (edge.subject_id, edge.object_id) if identifier in cwe]
    return all(cwe[identifier].props.get("source_release") == source_release for identifier in selected_endpoints)
