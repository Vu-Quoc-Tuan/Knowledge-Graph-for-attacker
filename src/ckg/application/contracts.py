"""Stable public contract for a grounded Module-1 vulnerability analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Module1Analysis:
    cve: dict[str, Any]
    weaknesses: tuple[dict[str, Any], ...]
    facets: dict[str, tuple[dict[str, Any], ...]]
    constraints: tuple[dict[str, Any], ...]
    historical_neighbors: tuple[dict[str, Any], ...]
    weakness_relationship: dict[str, Any] | None
    scenarios: tuple[dict[str, Any], ...]
    new_knowledge: dict[str, tuple[dict[str, Any], ...]]
    provenance: tuple[dict[str, Any], ...]
    abstentions: tuple[str, ...]
    local_subgraph: dict[str, Any]
