from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BetaPosterior:
    alpha: float = 1.0
    beta: float = 1.0

    def __post_init__(self) -> None:
        if self.alpha <= 0 or self.beta <= 0:
            raise ValueError("beta posterior parameters must be positive")

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    def positive(self, weight: float) -> "BetaPosterior":
        return BetaPosterior(self.alpha + weight, self.beta)

    def negative(self, weight: float) -> "BetaPosterior":
        return BetaPosterior(self.alpha, self.beta + weight)
