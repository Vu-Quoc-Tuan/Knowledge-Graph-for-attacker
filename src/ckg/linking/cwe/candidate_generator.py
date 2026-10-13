from __future__ import annotations

import re

from ckg.extraction.models import FacetCandidate
from ckg.graph.ports import GraphRepository


def generate_candidates(repository: GraphRepository, candidate: FacetCandidate, *, top_k: int = 20) -> tuple[tuple[str, float], ...]:
    """Exact IDs win; lexical fallback is a bounded candidate set, not a decision."""
    cwes = tuple(
        node
        for node in repository.nodes("CWE")
        if str(node.props.get("mapping_usage", "")).strip().lower()
        not in {"discouraged", "prohibited", "not allowed"}
    )
    if candidate.normalized_id and any(node.node_id == candidate.normalized_id for node in cwes):
        return ((candidate.normalized_id, 1.0),)
    parts = re.findall(r"[A-Z]+(?=[A-Z][a-z]|[0-9]|\b)|[A-Z]?[a-z0-9]+", candidate.value)
    query_tokens = set(p.lower() for p in parts if len(p) >= 3)
    if not query_tokens:
        query_tokens = set(re.findall(r"[a-z0-9]{3,}", candidate.value.lower()))
    scored = []
    for node in cwes:
        text = " ".join(str(node.props.get(field, "")) for field in ("name", "description")).lower()
        tokens = set(re.findall(r"[a-z0-9]{3,}", text))
        overlap = len(query_tokens & tokens) / len(query_tokens | tokens) if query_tokens else 0.0
        if overlap:
            scored.append((node.node_id, overlap))
    return tuple(sorted(scored, key=lambda item: (-item[1], item[0]))[:top_k])
