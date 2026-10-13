from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import warnings

import yaml


@dataclass(frozen=True)
class SubgraphBudget:
    cwe: int = 30
    capec: int = 15
    historical_cves: int = 30
    techniques: int = 20
    contexts: int = 30
    evidence: int = 30
    scenarios: int = 20
    max_depth: int = 2
    hard_max_nodes: int = 200
    max_query_paths: int = 1000
    timeout_seconds: float = 3.0

    def __post_init__(self) -> None:
        if any(value < 0 for value in self.__dict__.values()):
            raise ValueError("subgraph budgets cannot be negative")
        if self.hard_max_nodes > 200:
            raise ValueError("hard_max_nodes cannot exceed 200")
        if self.max_query_paths < 1 or self.timeout_seconds <= 0:
            raise ValueError("subgraph query path and timeout budgets must be positive")

    @classmethod
    def load(cls, path: Path | str | None = None) -> SubgraphBudget:
        if path is None:
            default_path = Path(__file__).resolve().parents[2] / "config" / "graph_budgets.yaml"
            if default_path.exists():
                path = default_path
        if path and Path(path).exists():
            try:
                data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
                sub = data.get("subgraph", {})
                return cls(
                    cwe=sub.get("cwe", 30),
                    capec=sub.get("capec", 15),
                    historical_cves=sub.get("historical_cves", 30),
                    techniques=sub.get("techniques", 20),
                    contexts=sub.get("contexts", 30),
                    evidence=sub.get("evidence", 30),
                    scenarios=sub.get("scenarios", 20),
                    max_depth=sub.get("max_depth", 2),
                    hard_max_nodes=sub.get("hard_max_nodes", 200),
                    max_query_paths=sub.get("max_query_paths", 1000),
                    timeout_seconds=float(sub.get("timeout_ms", 3000)) / 1000.0,
                )
            except Exception as exc:
                warnings.warn(
                    f"failed to load subgraph budgets from {path}: {exc}; using defaults",
                    RuntimeWarning,
                    stacklevel=2,
                )
        return cls()
