from ckg.scenario.contract import ScenarioCandidate


def rank(candidates: tuple[ScenarioCandidate, ...]) -> tuple[ScenarioCandidate, ...]:
    return tuple(
        sorted(
            candidates,
            key=lambda item: (
                -item.scenario.confidence.final,
                0 if (item.scenario.steps and len(item.scenario.steps) > 0) else 1,
                item.scenario.scenario_id,
            ),
        )
    )

