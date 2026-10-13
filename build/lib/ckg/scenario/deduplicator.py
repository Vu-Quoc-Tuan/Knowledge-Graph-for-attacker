from ckg.scenario.contract import ScenarioCandidate


def deduplicate(candidates: tuple[ScenarioCandidate, ...]) -> tuple[ScenarioCandidate, ...]:
    unique = {candidate.scenario.scenario_id: candidate for candidate in candidates}
    return tuple(unique[key] for key in sorted(unique))
