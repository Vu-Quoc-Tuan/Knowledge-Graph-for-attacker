from __future__ import annotations

from collections.abc import Callable


def run_ablations(sources: tuple[str, ...], evaluate: Callable[[frozenset[str]], float]) -> dict[str, float]:
    """Run full, incremental and leave-one-source-out with one evaluator contract."""
    all_sources = frozenset(sources)
    results = {"full": evaluate(all_sources)}
    for index in range(len(sources) + 1):
        results[f"incremental:{index}"] = evaluate(frozenset(sources[:index]))
    for source in sources:
        results[f"leave_one_out:{source}"] = evaluate(all_sources - {source})
    return results
