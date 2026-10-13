from pathlib import Path

from ai_producers.embedding_cache import EmbeddingCache


def test_embedding_cache_evicts_oldest_entries(tmp_path: Path) -> None:
    cache = EmbeddingCache(
        tmp_path / "embeddings.sqlite3",
        max_entries=2,
        ttl_seconds=None,
    )
    try:
        cache.put_many(
            "model",
            "revision",
            "passage",
            {"first": [1.0], "second": [2.0], "third": [3.0]},
        )
        assert cache.get_many(
            "model", "revision", "passage", ["first", "second", "third"]
        ) == {"second": [2.0], "third": [3.0]}
        assert cache._connection.execute(
            "SELECT count(*) FROM embeddings"
        ).fetchone()[0] == 2
    finally:
        cache.close()
