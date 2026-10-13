from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence

from ai_producers.embedding_cache import (
    EmbeddingCache,
    EmbeddingInputType,
    text_sha256,
)
from db.sink import GraphSink


class RetrievalError(RuntimeError):
    """Raised when a semantic shortlist cannot be produced safely."""


class EmbeddingProvider(Protocol):
    def embeddings(
        self,
        texts: Sequence[str],
        *,
        input_type: EmbeddingInputType,
    ) -> list[list[float]]: ...


@dataclass(frozen=True)
class CandidateWeakness:
    weakness_id: str
    canonical_text: str
    text_hash: str
    score: float
    node: Mapping[str, object]


def _collapsed(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def canonical_weakness_text(node: Mapping[str, object]) -> str:
    platforms_value = node.get("applicablePlatforms")
    platforms = (
        sorted(
            {
                _collapsed(item)
                for item in platforms_value
                if _collapsed(item)
            }
        )
        if isinstance(platforms_value, list)
        else []
    )
    fields = [
        ("ID", _collapsed(node.get("weaknessId"))),
        ("Name", _collapsed(node.get("name"))),
        ("Summary", _collapsed(node.get("summary"))),
        ("Abstraction", _collapsed(node.get("abstraction"))),
    ]
    lines = [
        f"{label}: {value}" for label, value in fields if value
    ]
    if platforms:
        lines.append("Applicable platforms:")
        lines.extend(f"- {platform}" for platform in platforms)
    return "\n".join(lines)


def _grounded(node: Mapping[str, object]) -> bool:
    return bool(
        _collapsed(node.get("summary"))
        and _collapsed(node.get("sourceUrl"))
    )


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right):
        raise RetrievalError("embedding vectors have inconsistent dimensions")
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0 or right_norm == 0:
        raise RetrievalError("embedding provider returned a zero-norm vector")
    return sum(a * b for a, b in zip(left, right)) / (
        left_norm * right_norm
    )


class EmbeddingRetriever:
    def __init__(
        self,
        provider: EmbeddingProvider,
        cache: EmbeddingCache,
        *,
        model_name: str,
        model_version: str,
        batch_size: int,
        max_top_k: int,
    ) -> None:
        if batch_size <= 0 or max_top_k <= 0:
            raise ValueError("batch_size and max_top_k must be positive")
        self.provider = provider
        self.cache = cache
        self.model_name = model_name
        self.model_version = model_version
        self.batch_size = batch_size
        self.max_top_k = max_top_k

    def candidates(
        self,
        sink: GraphSink,
        weakness_id: str,
        top_k: int | None = None,
    ) -> list[CandidateWeakness]:
        requested = self.max_top_k if top_k is None else top_k
        if (
            isinstance(requested, bool)
            or not isinstance(requested, int)
            or requested <= 0
            or requested > self.max_top_k
        ):
            raise RetrievalError(
                f"top_k must be between 1 and {self.max_top_k}"
            )
        subject = sink.get_node("Weakness", "weaknessId", weakness_id)
        if subject is None:
            raise RetrievalError(f"unknown Weakness: {weakness_id}")
        if not _grounded(subject):
            raise RetrievalError(
                f"{weakness_id} requires non-empty summary and sourceUrl"
            )

        candidates = [
            node
            for node in sink.nodes("Weakness")
            if node.get("weaknessId") != weakness_id
            and node.get("lifecycleStatus") != "deprecated"
            and _grounded(node)
        ]
        subject_text = canonical_weakness_text(subject)
        subject_hash = text_sha256(subject_text)
        candidate_texts = [
            canonical_weakness_text(node) for node in candidates
        ]
        candidate_hashes = [
            text_sha256(text) for text in candidate_texts
        ]
        query_vectors = self.cache.get_many(
            self.model_name,
            self.model_version,
            "query",
            [subject_hash],
        )
        passage_vectors = self.cache.get_many(
            self.model_name,
            self.model_version,
            "passage",
            candidate_hashes,
        )
        new_query_vectors: dict[str, list[float]] = {}
        if subject_hash not in query_vectors:
            embedded_subject = self.provider.embeddings(
                [subject_text],
                input_type="query",
            )
            if len(embedded_subject) != 1:
                raise RetrievalError(
                    "embedding provider returned the wrong vector count"
                )
            new_query_vectors[subject_hash] = embedded_subject[0]
            query_vectors.update(new_query_vectors)

        missing_passages = [
            (text_hash, text)
            for text_hash, text in zip(
                candidate_hashes,
                candidate_texts,
            )
            if text_hash not in passage_vectors
        ]
        new_passage_vectors: dict[str, list[float]] = {}
        for offset in range(
            0,
            len(missing_passages),
            self.batch_size,
        ):
            batch = missing_passages[offset : offset + self.batch_size]
            embedded = self.provider.embeddings(
                [text for _text_hash, text in batch],
                input_type="passage",
            )
            if len(embedded) != len(batch):
                raise RetrievalError(
                    "embedding provider returned the wrong vector count"
                )
            added = {
                text_hash: vector
                for (text_hash, _text), vector in zip(batch, embedded)
            }
            passage_vectors.update(added)
            new_passage_vectors.update(added)

        all_vectors = [
            query_vectors[subject_hash],
            *[
                passage_vectors[text_hash]
                for text_hash in candidate_hashes
            ],
        ]
        vector_dimensions = {len(vector) for vector in all_vectors}
        if len(vector_dimensions) != 1:
            raise RetrievalError(
                "embedding vectors have inconsistent dimensions"
            )
        if any(
            not vector
            or sum(value * value for value in vector) == 0
            for vector in all_vectors
        ):
            raise RetrievalError(
                "embedding provider returned a zero-norm vector"
            )
        self.cache.put_many_by_input_type(
            self.model_name,
            self.model_version,
            {
                "query": new_query_vectors,
                "passage": new_passage_vectors,
            },
        )
        subject_vector = query_vectors[subject_hash]
        ranked = [
            CandidateWeakness(
                weakness_id=str(node["weaknessId"]),
                canonical_text=text,
                text_hash=text_hash,
                score=_cosine(
                    subject_vector,
                    passage_vectors[text_hash],
                ),
                node=dict(node),
            )
            for node, text, text_hash in zip(
                candidates,
                candidate_texts,
                candidate_hashes,
            )
        ]
        ranked.sort(key=lambda item: (-item.score, item.weakness_id))
        return ranked[:requested]
