"""Shared construction boundary for the canonical v2 runtime."""

from __future__ import annotations

import os
from pathlib import Path

from ckg.api.main import CKGApplication
from ckg.config.settings import NEO4J_DEFAULT_URI
from ckg.graph.memory import InMemoryGraphRepository
from ckg.graph.neo4j.driver import Neo4jGraphRepository
from ckg.graph.ports import GraphRepository
from ckg.provenance.compact_details import COMPACT_DETAILS_DB_NAME, CompactDetailStore


def create_repository(
    *,
    memory: bool,
    uri: str | None = None,
    user: str | None = None,
    password: str | None = None,
    snapshot_root: str | None = None,
) -> GraphRepository:
    """Create the one repository implementation selected by the v2 runtime."""

    if memory:
        return InMemoryGraphRepository()

    configured_password = password or os.environ.get("NEO4J_PASSWORD", "change-me-please")
    repository = Neo4jGraphRepository(
        uri or os.environ.get("NEO4J_URI", NEO4J_DEFAULT_URI),
        user or os.environ.get("NEO4J_USER", "neo4j"),
        configured_password,
    )
    root = snapshot_root or os.environ.get("SOURCE_SNAPSHOT_ROOT", "registry/upstream_snapshots")
    repository.set_compact_detail_store(CompactDetailStore(Path(root) / COMPACT_DETAILS_DB_NAME))
    return repository


def create_application(repository: GraphRepository, *, snapshot_root: str) -> CKGApplication:
    """Construct the canonical v2 application around a selected repository."""

    return CKGApplication(repository, snapshot_root=snapshot_root)
