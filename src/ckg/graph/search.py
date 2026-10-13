"""Shared filtering and alias folding for technology-to-CVE searches."""

from __future__ import annotations

from datetime import datetime
import re
import unicodedata
from typing import Iterable

from ckg.graph.models import GraphEdge, GraphNode, VulnerabilitySearchMatch


_VULNERABILITY_LABELS = frozenset({"CVE", "GHSA"})
_SUPPRESSED_STATES = frozenset({"REJECTED", "WITHDRAWN"})
_PRODUCT_FIELDS = ("name", "package_name", "vendor", "cpe_uri", "aliases")


def normalize_search_term(value: str) -> str:
    """Normalize a product query and product identity for shared matching."""
    normalized = unicodedata.normalize("NFKC", str(value)).casefold()
    normalized = normalized.replace("\\", " ")
    normalized = re.sub(r"[^\w]+", " ", normalized, flags=re.UNICODE)
    return " ".join(normalized.split())


def _property_values(props: dict[str, object], field: str) -> tuple[str, ...]:
    value = props.get(field)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value if item is not None)
    return (str(value),) if value is not None else ()


def product_match(props: dict[str, object], term: str) -> tuple[float, str] | None:
    """Return a deterministic relevance/reason pair for a product identity."""
    normalized_term = normalize_search_term(term)
    if not normalized_term:
        return None
    tokens = normalized_term.split()
    identity_values = {
        field: tuple(normalize_search_term(value) for value in _property_values(props, field))
        for field in _PRODUCT_FIELDS
    }
    name_values = identity_values["name"] + identity_values["package_name"]
    alias_values = identity_values["aliases"] + identity_values["cpe_uri"]
    vendor_values = identity_values["vendor"]

    if normalized_term in name_values:
        return 1.0, "exact_product"
    if normalized_term in alias_values:
        return 0.95, "alias"
    if any(value.startswith(normalized_term) for value in name_values):
        return 0.85, "product_prefix"
    if normalized_term in vendor_values:
        return 0.75, "vendor"
    if any(normalized_term in value for value in vendor_values):
        return 0.7, "vendor"
    if any(all(token in value for token in tokens) for value in name_values + alias_values + vendor_values):
        return 0.5, "substring"
    return None


def _published_year(value: object) -> int | None:
    if isinstance(value, datetime):
        return value.year
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).year
    except ValueError:
        return None


def _canonical_id(node: GraphNode) -> str:
    aliases = node.props.get("aliases")
    candidates = [node.node_id]
    if isinstance(aliases, (list, tuple)):
        candidates.extend(str(alias) for alias in aliases)
    cves = sorted(candidate for candidate in candidates if candidate.startswith("CVE-"))
    return cves[0] if cves else node.node_id


def _state_is_active(vulnerability: GraphNode, sources: Iterable[GraphNode]) -> bool:
    states: list[str] = []
    current_state = vulnerability.props.get("current_source_state")
    if current_state:
        states.append(str(current_state).upper())
    for source in sources:
        state = source.props.get("state")
        if state:
            states.append(str(state).upper())
    return not states or any(state not in _SUPPRESSED_STATES for state in states)


def _version_matches_products(edge: GraphEdge, product_ids: set[str]) -> bool:
    """An unscoped legacy version remains visible for compatibility."""
    listed = edge.props.get("product_ids")
    scoped = {value for value in listed if isinstance(value, str)} if isinstance(listed, (list, tuple)) else set()
    single = edge.props.get("product_id")
    if isinstance(single, str) and single:
        scoped.add(single)
    return not scoped or bool(scoped & product_ids)


def merge_vulnerability_matches(
    matches: Iterable[VulnerabilitySearchMatch], *, limit: int
) -> list[VulnerabilitySearchMatch]:
    """Fold CVE/GHSA aliases without discarding product/source evidence."""
    grouped: dict[str, list[VulnerabilitySearchMatch]] = {}
    for match in matches:
        grouped.setdefault(_canonical_id(match.vulnerability), []).append(match)

    merged: list[VulnerabilitySearchMatch] = []
    for canonical_id, group in grouped.items():
        active_sources = tuple(
            source
            for match in group
            for source in match.sources
        )
        if not _state_is_active(group[0].vulnerability, active_sources):
            continue
        canonical = min(
            (match.vulnerability for match in group),
            key=lambda node: (
                0 if _published_year(node.props.get("published_at")) is not None else 1,
                0 if node.label == "CVE" else 1,
                node.node_id,
            ),
        )
        best_match = max(
            group,
            key=lambda match: (
                match.relevance,
                _published_year(match.vulnerability.props.get("published_at")) or 0,
                match.vulnerability.node_id,
            ),
        )
        aliases: set[str] = set()
        products: dict[str, GraphNode] = {}
        versions: dict[str, GraphNode] = {}
        sources: dict[str, GraphNode] = {}
        for match in group:
            aliases.add(match.vulnerability.node_id)
            raw_aliases = match.vulnerability.props.get("aliases")
            if isinstance(raw_aliases, (list, tuple)):
                aliases.update(str(alias) for alias in raw_aliases)
            products.update({product.node_id: product for product in match.products})
            versions.update({version.node_id: version for version in match.versions})
            sources.update({source.node_id: source for source in match.sources})
        merged_props = dict(canonical.props)
        merged_props["aliases"] = sorted(alias for alias in aliases if alias != canonical_id)
        merged.append(
            VulnerabilitySearchMatch(
                vulnerability=GraphNode(label=canonical.label, node_id=canonical_id, props=merged_props),
                products=tuple(products.values()),
                versions=tuple(versions.values()),
                sources=tuple(sources.values()),
                relevance=best_match.relevance,
                match_reason=best_match.match_reason,
            )
        )
    merged.sort(
        key=lambda match: (
            match.relevance,
            _published_year(match.vulnerability.props.get("published_at")) or 0,
            match.vulnerability.node_id,
        ),
        reverse=True,
    )
    return merged[:limit]


def search_vulnerabilities(
    nodes: Iterable[GraphNode],
    edges: Iterable[GraphEdge],
    *,
    technology: str,
    from_year: int,
    to_year: int,
    limit: int,
) -> list[VulnerabilitySearchMatch]:
    term = normalize_search_term(technology)
    if not term:
        raise ValueError("technology must not be empty")
    if from_year > to_year:
        raise ValueError("from_year must be less than or equal to to_year")
    if limit < 1:
        raise ValueError("limit must be at least 1")

    node_map = {node.node_id: node for node in nodes}
    edge_list = list(edges)
    products_by_vulnerability: dict[str, dict[str, GraphNode]] = {}
    versions_by_vulnerability: dict[str, list[tuple[GraphNode, GraphEdge]]] = {}
    sources_by_vulnerability: dict[str, dict[str, GraphNode]] = {}
    scores_by_vulnerability: dict[str, tuple[float, str]] = {}
    for edge in edge_list:
        if edge.props.get("stale") is True:
            continue
        subject = node_map.get(edge.subject_id)
        target = node_map.get(edge.object_id)
        if subject is None or target is None:
            continue
        if edge.edge_type == "AFFECTS" and subject.label in _VULNERABILITY_LABELS and target.label == "Product":
            match = product_match(target.props, term)
            if match is not None:
                products_by_vulnerability.setdefault(subject.node_id, {})[target.node_id] = target
                current = scores_by_vulnerability.get(subject.node_id)
                if current is None or match > current:
                    scores_by_vulnerability[subject.node_id] = match
        elif edge.edge_type == "AFFECTS_VERSION" and subject.label in _VULNERABILITY_LABELS and target.label == "VersionRange":
            versions_by_vulnerability.setdefault(subject.node_id, []).append((target, edge))
        elif edge.edge_type == "DESCRIBES" and subject.label == "VulnerabilitySourceRecord" and target.label in _VULNERABILITY_LABELS:
            sources_by_vulnerability.setdefault(target.node_id, {})[subject.node_id] = subject

    matches: list[VulnerabilitySearchMatch] = []
    for node_id, products in products_by_vulnerability.items():
        vulnerability = node_map[node_id]
        year = _published_year(vulnerability.props.get("published_at"))
        if year is None or not from_year <= year <= to_year:
            continue
        sources = tuple(sources_by_vulnerability.get(node_id, {}).values())
        if not _state_is_active(vulnerability, sources):
            continue
        matches.append(
            VulnerabilitySearchMatch(
                vulnerability=vulnerability,
                products=tuple(products.values()),
                versions=tuple({
                    version.node_id: version
                    for version, edge in versions_by_vulnerability.get(node_id, [])
                    if _version_matches_products(edge, set(products))
                }.values()),
                sources=sources,
                relevance=scores_by_vulnerability[node_id][0],
                match_reason=scores_by_vulnerability[node_id][1],
            )
        )
    return merge_vulnerability_matches(matches, limit=limit)
