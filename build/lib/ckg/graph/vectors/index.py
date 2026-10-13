from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class InMemoryVectorIndex:
    vectors: dict[str, tuple[float, ...]] = field(default_factory=dict)

    def upsert(self, identifier: str, vector: tuple[float, ...]) -> None:
        self.vectors[identifier] = vector

    def search(self, vector: tuple[float, ...], *, top_k: int) -> tuple[tuple[str, float], ...]:
        def similarity(other: tuple[float, ...]) -> float:
            if len(other) != len(vector):
                raise ValueError("vector dimensions do not match")
            return sum(left * right for left, right in zip(vector, other))
        return tuple(sorted(((identifier, similarity(other)) for identifier, other in self.vectors.items()), key=lambda item: (-item[1], item[0]))[:top_k])
