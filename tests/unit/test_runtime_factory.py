from pathlib import Path

import pytest

from ckg.graph.memory import InMemoryGraphRepository
from ckg.provenance.compact_details import COMPACT_DETAILS_DB_NAME, CompactDetailStore
from ckg.runtime import create_application, create_repository


def test_memory_factory_returns_v2_repository() -> None:
    repository = create_repository(memory=True)
    assert isinstance(repository, InMemoryGraphRepository)
    assert repository.backend_name == "in-memory"


def test_application_reports_v2_schema(tmp_path: Path) -> None:
    app = create_application(InMemoryGraphRepository(), snapshot_root=str(tmp_path))
    assert app.backend_info() == {"graphSchema": "ckg-v2", "backend": "in-memory"}


def test_application_requires_canonical_ui_assets(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from ckg import api

    monkeypatch.setattr(api.main.Path, "resolve", lambda self: tmp_path / "missing")
    with pytest.raises(FileNotFoundError, match="canonical v2 UI assets"):
        create_application(InMemoryGraphRepository(), snapshot_root=str(tmp_path))


def test_default_neo4j_runtime_uses_snapshot_root_for_revisions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from ckg import runtime

    class FakeNeo4jRepository(InMemoryGraphRepository):
        def __init__(self, uri: str, user: str, password: str) -> None:
            super().__init__()
            self.connection = (uri, user, password)

        @property
        def backend_name(self) -> str:
            return "neo4j"

    monkeypatch.setattr(runtime, "Neo4jGraphRepository", FakeNeo4jRepository)
    monkeypatch.setenv("SOURCE_SNAPSHOT_ROOT", str(tmp_path))
    repository = create_repository(memory=False, uri="bolt://example:7687", user="test", password="test")

    assert repository.connection == ("bolt://example:7687", "test", "test")
    assert isinstance(repository._compact_detail_store, CompactDetailStore)
    assert repository._compact_detail_store.path == tmp_path / COMPACT_DETAILS_DB_NAME
    assert not repository._compact_detail_store.path.exists()

    other_root = tmp_path / "other"
    create_application(repository, snapshot_root=str(other_root))
    assert repository._compact_detail_store.path == other_root / COMPACT_DETAILS_DB_NAME


def test_cli_passes_snapshot_root_to_repository(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import argparse
    from ckg import __main__ as cli

    seen: dict[str, object] = {}

    def fake_create_repository(**kwargs: object) -> InMemoryGraphRepository:
        seen.update(kwargs)
        return InMemoryGraphRepository()

    monkeypatch.setattr(cli, "create_repository", fake_create_repository)
    cli._get_repository(argparse.Namespace(memory=False, snapshot_root=str(tmp_path)))
    assert seen["snapshot_root"] == str(tmp_path)
