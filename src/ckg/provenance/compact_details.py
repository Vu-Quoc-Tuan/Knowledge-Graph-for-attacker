"""Lossless sidecar storage for graph details that are not traversal entities.

The focused graph keeps semantic entities and source-backed relationships that
are useful for retrieval.  Some imported structures are still valuable for
audit and re-materialisation but are too verbose for the active graph: CAPEC
steps/prerequisites, CWE taxonomy groups and content revisions, and PATT
document/evidence records.
This module stores those records as JSON in a small SQLite sidecar while
retaining their stable identities, properties, relationships, and snapshot
digests.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ckg.graph.models import GraphEdge, GraphNode


COMPACT_DETAILS_DB_NAME = "compact_details.sqlite3"
_PATT_EVIDENCE_KINDS = frozenset({"patt_markdown", "patt_wordlist"})
_COMPACT_NODE_LABELS = frozenset(
    {
        "AttackStep",
        "AttackPrerequisite",
        "CWECategory",
        "CWEView",
        "CWEContentRevision",
        "CAPECContentRevision",
        "PATTDocument",
    }
)


def is_compact_detail_node(node: GraphNode) -> bool:
    """Return whether ``node`` belongs in the compact sidecar."""

    return node.label in _COMPACT_NODE_LABELS or (
        node.label == "Evidence" and node.props.get("kind") in _PATT_EVIDENCE_KINDS
    )


def _detail_kind(node: GraphNode) -> str:
    if node.label == "Evidence":
        return "patt_evidence"
    return {
        "AttackStep": "capec_attack_step",
        "AttackPrerequisite": "capec_prerequisite",
        "CWECategory": "cwe_taxonomy_group",
        "CWEView": "cwe_taxonomy_group",
        "CWEContentRevision": "cwe_content_revision",
        "CAPECContentRevision": "capec_content_revision",
        "PATTDocument": "patt_document",
    }[node.label]


def _source_digest(payload: Mapping[str, Any]) -> str | None:
    for key in ("source_snapshot_digest", "content_digest"):
        value = payload.get(key)
        if isinstance(value, str) and value.startswith("sha256:"):
            return value
    return None


def _retrieved_at(payload: Mapping[str, Any]) -> str | None:
    value = payload.get("retrieved_at")
    return value if isinstance(value, str) else None


def collect_compact_detail_records(
    nodes: Iterable[GraphNode],
    edges: Iterable[GraphEdge],
) -> tuple[dict[str, Any], ...]:
    """Collect a deterministic, lossless sidecar representation.

    Node and edge payloads are kept as their canonical JSON model dumps.  An
    edge is included whenever either endpoint is compacted, so removing the
    detail nodes from Neo4j cannot silently discard ordering, provenance, or
    source relationships.
    """

    all_nodes = tuple(nodes)
    all_edges = tuple(edges)
    by_id = {node.node_id: node for node in all_nodes}
    records: dict[str, dict[str, Any]] = {}

    for node in all_nodes:
        if not is_compact_detail_node(node):
            continue
        payload = node.model_dump(mode="json")
        records[node.node_id] = {
            "detail_id": node.node_id,
            "detail_kind": _detail_kind(node),
            "parent_id": (
                node.props.get("capec_id")
                or node.props.get("slice_cwe_id")
                or node.props.get("canonical_id")
                or node.node_id
            ),
            "relation_id": None,
            "source_snapshot_digest": _source_digest(node.props),
            "retrieved_at": _retrieved_at(node.props),
            "payload": payload,
        }

    for edge in all_edges:
        subject = by_id.get(edge.subject_id)
        object_ = by_id.get(edge.object_id)
        if subject is None or object_ is None:
            continue
        if not is_compact_detail_node(subject) and not is_compact_detail_node(object_):
            continue
        payload = edge.model_dump(mode="json")
        records[f"edge:{edge.edge_id}"] = {
            "detail_id": f"edge:{edge.edge_id}",
            "detail_kind": "compact_edge",
            "parent_id": edge.subject_id,
            "relation_id": edge.edge_id,
            "source_snapshot_digest": _source_digest(edge.props),
            "retrieved_at": _retrieved_at(edge.props),
            "payload": {
                "edge": payload,
                "subject_label": subject.label,
                "object_label": object_.label,
            },
        }

    return tuple(records[key] for key in sorted(records))


@dataclass(frozen=True)
class CompactDetailReport:
    record_count: int
    node_count: int
    edge_count: int
    by_kind: dict[str, int]


class CompactDetailStore:
    """SQLite store for compacted graph detail records."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS compact_details (
                detail_id TEXT PRIMARY KEY,
                detail_kind TEXT NOT NULL,
                parent_id TEXT,
                relation_id TEXT,
                source_snapshot_digest TEXT,
                retrieved_at TEXT,
                payload_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_compact_details_kind_parent "
            "ON compact_details (detail_kind, parent_id, detail_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_compact_details_snapshot "
            "ON compact_details (source_snapshot_digest)"
        )
        connection.commit()
        return connection

    @staticmethod
    def _row(record: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            str(record["detail_id"]),
            str(record["detail_kind"]),
            record.get("parent_id"),
            record.get("relation_id"),
            record.get("source_snapshot_digest"),
            record.get("retrieved_at"),
            json.dumps(record["payload"], ensure_ascii=False, sort_keys=True),
        )

    def replace_all(self, records: Iterable[Mapping[str, Any]]) -> CompactDetailReport:
        """Atomically replace the sidecar with the current source projection."""

        rows = [self._row(record) for record in records]
        connection = self._connect()
        try:
            connection.execute("DELETE FROM compact_details")
            if rows:
                connection.executemany(
                    """
                    INSERT INTO compact_details (
                        detail_id, detail_kind, parent_id, relation_id,
                        source_snapshot_digest, retrieved_at, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
            connection.commit()
        finally:
            connection.close()
        return self.report()

    def put_many(self, records: Iterable[Mapping[str, Any]]) -> CompactDetailReport:
        """Upsert records for callers that build a sidecar incrementally."""

        rows = [self._row(record) for record in records]
        connection = self._connect()
        try:
            if rows:
                connection.executemany(
                    """
                    INSERT INTO compact_details (
                        detail_id, detail_kind, parent_id, relation_id,
                        source_snapshot_digest, retrieved_at, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(detail_id) DO UPDATE SET
                        detail_kind=excluded.detail_kind,
                        parent_id=excluded.parent_id,
                        relation_id=excluded.relation_id,
                        source_snapshot_digest=excluded.source_snapshot_digest,
                        retrieved_at=excluded.retrieved_at,
                        payload_json=excluded.payload_json
                    """,
                    rows,
                )
            connection.commit()
        finally:
            connection.close()
        return self.report()

    def query(
        self,
        *,
        detail_kind: str | None = None,
        parent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[str] = []
        if detail_kind is not None:
            clauses.append("detail_kind = ?")
            parameters.append(detail_kind)
        if parent_id is not None:
            clauses.append("parent_id = ?")
            parameters.append(parent_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM compact_details"
                f"{where} ORDER BY detail_kind, detail_id",
                parameters,
            ).fetchall()
        finally:
            connection.close()
        return [
            {
                "detail_id": row["detail_id"],
                "detail_kind": row["detail_kind"],
                "parent_id": row["parent_id"],
                "relation_id": row["relation_id"],
                "source_snapshot_digest": row["source_snapshot_digest"],
                "retrieved_at": row["retrieved_at"],
                "payload": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def canonical_revisions(self, catalog: str) -> list[GraphNode]:
        """Read validated revision nodes without creating an absent sidecar.

        Malformed records are an error: a partial historical projection would
        otherwise look like a valid answer to an as-of query.
        """

        kinds = {"CWE": "cwe_content_revision", "CAPEC": "capec_content_revision"}
        if catalog not in kinds:
            raise ValueError(f"unsupported canonical catalog: {catalog}")
        if not self.path.is_file():
            return []
        try:
            connection = sqlite3.connect(f"{self.path.resolve().as_uri()}?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            try:
                rows = connection.execute(
                    "SELECT detail_id, parent_id, source_snapshot_digest, retrieved_at, payload_json "
                    "FROM compact_details WHERE detail_kind = ? ORDER BY detail_id",
                    (kinds[catalog],),
                ).fetchall()
            finally:
                connection.close()
            revisions: list[GraphNode] = []
            for row in rows:
                payload = json.loads(row["payload_json"])
                node = GraphNode.model_validate(payload)
                if (
                    node.label != f"{catalog}ContentRevision"
                    or node.node_id != row["detail_id"]
                    or not isinstance(node.props.get("canonical_id"), str)
                    or not node.props["canonical_id"].startswith(f"{catalog}-")
                    or node.props["canonical_id"] != row["parent_id"]
                    or _source_digest(node.props) != row["source_snapshot_digest"]
                    or not isinstance(node.props.get("retrieved_at"), str)
                    or node.props["retrieved_at"] != row["retrieved_at"]
                ):
                    raise ValueError("inconsistent canonical revision record")
                datetime.fromisoformat(node.props["retrieved_at"].replace("Z", "+00:00"))
                revisions.append(node)
            return revisions
        except (sqlite3.Error, ValueError, TypeError, KeyError) as error:
            raise ValueError(f"invalid {catalog} content revisions in {self.path}") from error

    def snapshot_digests(self) -> set[str]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT DISTINCT source_snapshot_digest "
                "FROM compact_details WHERE source_snapshot_digest IS NOT NULL"
            ).fetchall()
        finally:
            connection.close()
        return {str(row[0]) for row in rows}

    def report(self) -> CompactDetailReport:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT detail_kind, COUNT(*) AS count "
                "FROM compact_details GROUP BY detail_kind ORDER BY detail_kind"
            ).fetchall()
        finally:
            connection.close()
        by_kind = {str(row["detail_kind"]): int(row["count"]) for row in rows}
        node_count = sum(
            count for kind, count in by_kind.items() if kind != "compact_edge"
        )
        edge_count = by_kind.get("compact_edge", 0)
        return CompactDetailReport(
            record_count=sum(by_kind.values()),
            node_count=node_count,
            edge_count=edge_count,
            by_kind=by_kind,
        )


def export_compact_details(
    nodes: Iterable[GraphNode],
    edges: Iterable[GraphEdge],
    store: CompactDetailStore,
) -> CompactDetailReport:
    """Write the compact details represented by a graph snapshot."""

    return store.replace_all(collect_compact_detail_records(nodes, edges))


def merge_compact_detail_records(
    *record_sets: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Merge details while preserving first-seen canonical revision availability.

    Reimporting the same immutable revision may carry a later retrieved_at.
    The existing sidecar is passed first by rebuild, so that replay cannot
    move the revision's historical availability date forward.
    """

    merged: dict[str, dict[str, Any]] = {}
    for records in record_sets:
        for record in records:
            detail_id = str(record["detail_id"])
            prior = merged.get(detail_id)
            if prior is not None and prior["detail_kind"] in {
                "cwe_content_revision", "capec_content_revision"
            }:
                continue
            merged[detail_id] = dict(record)
    return tuple(merged[key] for key in sorted(merged))


__all__ = [
    "COMPACT_DETAILS_DB_NAME",
    "CompactDetailReport",
    "CompactDetailStore",
    "collect_compact_detail_records",
    "export_compact_details",
    "is_compact_detail_node",
    "merge_compact_detail_records",
]
