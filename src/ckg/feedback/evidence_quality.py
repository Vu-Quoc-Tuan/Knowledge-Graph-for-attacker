from __future__ import annotations

from dataclasses import dataclass

from ckg.domain.entities.observation import ObservationResult


@dataclass(frozen=True)
class ObservationQuality:
    oracle_observable: bool
    environment_complete: bool
    source_evidence_present: bool

    @property
    def weight(self) -> float:
        # A negative NO_SIGNAL needs all three conditions. A positive observed
        # callback still requires evidence, but may work with partial snapshot.
        return (int(self.oracle_observable) + int(self.environment_complete) + int(self.source_evidence_present)) / 3


def update_weight(result: ObservationResult, quality: ObservationQuality) -> float:
    if result == ObservationResult.REPRODUCED:
        return quality.weight if quality.source_evidence_present else 0.0
    if result == ObservationResult.NO_SIGNAL:
        # A missing signal says nothing if the executed probe itself cannot be
        # traced back to source evidence, even when an oracle was observable.
        return (
            quality.weight
            if quality.oracle_observable
            and quality.environment_complete
            and quality.source_evidence_present
            else 0.0
        )
    return 0.0
