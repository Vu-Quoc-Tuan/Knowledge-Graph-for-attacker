from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
from pathlib import Path
from typing import Literal, Mapping, Sequence, cast


EmbeddingInputType = Literal["query", "passage"]


class EmbeddingCacheError(RuntimeError):
    """Raised when cached embedding data cannot be trusted."""


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validated_input_type(value: object) -> EmbeddingInputType:
    if value not in {"query", "passage"}:
        raise ValueError("input_type must be query or passage")
    return cast(EmbeddingInputType, value)


def _validated_vector(
    value: object,
    *,
    expected_dimensions: int | None,
) -> list[float]:
    if not isinstance(value, list) or not value:
        raise EmbeddingCacheError("embedding must be a non-empty JSON array")
    if any(
        isinstance(item, bool)
        or not isinstance(item, (int, float))
        or not math.isfinite(item)
        for item in value
    ):
        raise EmbeddingCacheError(
            "embedding must contain only finite numbers"
        )
    if expected_dimensions is not None and len(value) != expected_dimensions:
        raise EmbeddingCacheError(
            "embedding dimensions do not match the configured dimensions"
        )
    return [float(item) for item in value]


class EmbeddingCache:
    def __init__(
        self,
        path: str | Path,
        *,
        expected_dimensions: int | None = None,
        max_entries: int | None = 50_000,
        ttl_seconds: float | None = 30 * 24 * 60 * 60,
    ) -> None:
        self.path = Path(path)
        self.expected_dimensions = expected_dimensions
        if max_entries is not None and max_entries < 1:
            raise ValueError("max_entries must be positive when set")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive when set")
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._closed = False
        connection: sqlite3.Connection | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path)
            self._connection = connection
            connection.execute("PRAGMA auto_vacuum = INCREMENTAL")
            expected_columns = {
                "model_name",
                "model_version",
                "input_type",
                "text_hash",
                "dimensions",
                "vector_json",
                "created_at",
                "last_accessed_at",
            }
            current_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(embeddings)"
                ).fetchall()
            }
            if current_columns and current_columns != expected_columns:
                # This cache is derived and rebuildable. Recreate an
                # incompatible pre-release schema rather than guessing how to
                # migrate vectors.
                connection.execute("DROP TABLE embeddings")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS embeddings (
                    model_name TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    input_type TEXT NOT NULL
                        CHECK (input_type IN ('query', 'passage')),
                    text_hash TEXT NOT NULL,
                    dimensions INTEGER NOT NULL CHECK (dimensions > 0),
                    vector_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    last_accessed_at REAL NOT NULL,
                    PRIMARY KEY (
                        model_name,
                        model_version,
                        input_type,
                        text_hash
                    )
                )
                """
            )
            connection.commit()
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            self._closed = True
            raise EmbeddingCacheError(
                f"cannot initialize embedding cache {self.path}"
            ) from exc

    def __enter__(self) -> "EmbeddingCache":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise EmbeddingCacheError("embedding cache is closed")

    def get_many(
        self,
        model_name: str,
        model_version: str,
        input_type: EmbeddingInputType,
        text_hashes: Sequence[str],
    ) -> dict[str, list[float]]:
        self._ensure_open()
        role = _validated_input_type(input_type)
        unique_hashes = list(dict.fromkeys(text_hashes))
        if not unique_hashes:
            return {}
        placeholders = ", ".join("?" for _ in unique_hashes)
        try:
            self._prune()
            rows = self._connection.execute(
                f"""
                SELECT text_hash, dimensions, vector_json
                FROM embeddings
                WHERE model_name = ?
                  AND model_version = ?
                  AND input_type = ?
                  AND text_hash IN ({placeholders})
                """,
                (model_name, model_version, role, *unique_hashes),
            ).fetchall()
        except sqlite3.Error as exc:
            raise EmbeddingCacheError(
                "failed to read the embedding cache"
            ) from exc
        result: dict[str, list[float]] = {}
        for text_hash, stored_dimensions, raw_vector in rows:
            try:
                decoded = json.loads(raw_vector)
            except (TypeError, ValueError) as exc:
                raise EmbeddingCacheError(
                    f"cached embedding {text_hash} is invalid JSON"
                ) from exc
            vector = _validated_vector(
                decoded,
                expected_dimensions=self.expected_dimensions,
            )
            if (
                isinstance(stored_dimensions, bool)
                or not isinstance(stored_dimensions, int)
                or stored_dimensions != len(vector)
            ):
                raise EmbeddingCacheError(
                    f"cached embedding {text_hash} has corrupt dimensions"
                )
            result[text_hash] = vector
        if result:
            try:
                now = time.time()
                result_placeholders = ", ".join("?" for _ in result)
                with self._connection:
                    self._connection.execute(
                        f"""
                        UPDATE embeddings
                        SET last_accessed_at = ?
                        WHERE model_name = ?
                          AND model_version = ?
                          AND input_type = ?
                          AND text_hash IN ({result_placeholders})
                        """,
                        (now, model_name, model_version, role, *result),
                    )
            except sqlite3.Error as exc:
                raise EmbeddingCacheError(
                    "failed to update embedding cache access times"
                ) from exc
        return result

    def _prune(self) -> None:
        """Delete expired/least-recently-used rows and reclaim free pages."""
        now = time.time()
        deleted = 0
        try:
            with self._connection:
                if self.ttl_seconds is not None:
                    cursor = self._connection.execute(
                        "DELETE FROM embeddings WHERE last_accessed_at < ?",
                        (now - self.ttl_seconds,),
                    )
                    deleted += cursor.rowcount
                if self.max_entries is not None:
                    count = self._connection.execute(
                        "SELECT count(*) FROM embeddings"
                    ).fetchone()[0]
                    excess = max(0, count - self.max_entries)
                    if excess:
                        cursor = self._connection.execute(
                            """
                            DELETE FROM embeddings
                            WHERE rowid IN (
                                SELECT rowid
                                FROM embeddings
                                ORDER BY last_accessed_at ASC, rowid ASC
                                LIMIT ?
                            )
                            """,
                            (excess,),
                        )
                        deleted += cursor.rowcount
                if deleted:
                    self._connection.execute("PRAGMA incremental_vacuum")
        except sqlite3.Error as exc:
            raise EmbeddingCacheError(
                "failed to evict old embedding cache entries"
            ) from exc

    def put_many(
        self,
        model_name: str,
        model_version: str,
        input_type: EmbeddingInputType,
        vectors: Mapping[str, Sequence[float]],
    ) -> None:
        self.put_many_by_input_type(
            model_name,
            model_version,
            {input_type: vectors},
        )

    def put_many_by_input_type(
        self,
        model_name: str,
        model_version: str,
        vectors_by_input_type: Mapping[
            EmbeddingInputType,
            Mapping[str, Sequence[float]],
        ],
    ) -> None:
        self._ensure_open()
        roles = {
            input_type: _validated_input_type(input_type)
            for input_type in vectors_by_input_type
        }
        now = time.time()
        validated = [
            (
                model_name,
                model_version,
                roles[input_type],
                text_hash,
                len(vector),
                json.dumps(
                    _validated_vector(
                        list(vector),
                        expected_dimensions=self.expected_dimensions,
                    ),
                    separators=(",", ":"),
                    allow_nan=False,
                ),
                now,
                now,
            )
            for input_type, vectors in vectors_by_input_type.items()
            for text_hash, vector in vectors.items()
        ]
        if not validated:
            return
        try:
            with self._connection:
                self._connection.executemany(
                    """
                    INSERT INTO embeddings
                        (
                            model_name,
                            model_version,
                            input_type,
                            text_hash,
                            dimensions,
                            vector_json,
                            created_at,
                            last_accessed_at
                        )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (
                        model_name,
                        model_version,
                        input_type,
                        text_hash
                    )
                    DO UPDATE SET
                        dimensions = excluded.dimensions,
                        vector_json = excluded.vector_json,
                        last_accessed_at = excluded.last_accessed_at
                    """,
                    validated,
                )
            self._prune()
        except sqlite3.Error as exc:
            raise EmbeddingCacheError(
                "failed to store embeddings transactionally"
            ) from exc

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._closed = True
