"""Compact, provenance-preserving index for PATT payload references.

Raw payload candidates are useful for human review but are too numerous and
too granular to be graph entities.  This small SQLite sidecar keeps the exact
candidate plus its source locator while the canonical graph stores only the
document/family/evidence structure.  The index is deliberately standard
library only so it works in offline builds and in the in-memory repository.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any


DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def payload_digest(value: str) -> str:
    """Return a stable digest for the byte-exact payload text."""

    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


class PATTIndex:
    """SQLite index for source-backed, untested PATT references."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS patt_payloads (
                payload_id TEXT PRIMARY KEY,
                cwe_id TEXT NOT NULL,
                family_key TEXT NOT NULL,
                family_name TEXT NOT NULL,
                technology TEXT,
                value TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                source_file TEXT NOT NULL,
                source_url TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                source_snapshot_digest TEXT NOT NULL,
                section_heading TEXT NOT NULL,
                locator TEXT NOT NULL,
                extraction TEXT NOT NULL,
                origin TEXT NOT NULL,
                curation_status TEXT NOT NULL,
                validation_status TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_patt_payloads_cwe_family "
            "ON patt_payloads (cwe_id, family_key, payload_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_patt_payloads_technology "
            "ON patt_payloads (technology, payload_id)"
        )
        connection.commit()
        return connection

    @staticmethod
    def _record(record: Mapping[str, Any]) -> tuple[Any, ...]:
        value = str(record["value"])
        return (
            str(record["payload_id"]),
            str(record["cwe_id"]),
            str(record["family_key"]),
            str(record["family_name"]),
            record.get("technology"),
            value,
            str(record.get("payload_digest") or payload_digest(value)),
            str(record["source_file"]),
            str(record["source_url"]),
            str(record["source_revision"]),
            str(record["source_kind"]),
            str(record["source_snapshot_digest"]),
            str(record.get("section_heading") or ""),
            str(record["locator"]),
            str(record["extraction"]),
            str(record.get("origin") or "patt"),
            str(record.get("curation_status") or "upstream_curated"),
            str(record.get("validation_status") or "untested"),
        )

    def put_many(self, records: Iterable[Mapping[str, Any]]) -> int:
        """Atomically upsert records and return the number of supplied rows."""

        rows = [self._record(record) for record in records]
        if not rows:
            connection = self._connect()
            connection.close()
            return 0
        connection = self._connect()
        try:
            connection.executemany(
                """
                INSERT INTO patt_payloads (
                    payload_id, cwe_id, family_key, family_name, technology,
                    value, payload_digest, source_file, source_url,
                    source_revision, source_kind, source_snapshot_digest,
                    section_heading, locator, extraction, origin,
                    curation_status, validation_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(payload_id) DO UPDATE SET
                    cwe_id=excluded.cwe_id,
                    family_key=excluded.family_key,
                    family_name=excluded.family_name,
                    technology=excluded.technology,
                    value=excluded.value,
                    payload_digest=excluded.payload_digest,
                    source_file=excluded.source_file,
                    source_url=excluded.source_url,
                    source_revision=excluded.source_revision,
                    source_kind=excluded.source_kind,
                    source_snapshot_digest=excluded.source_snapshot_digest,
                    section_heading=excluded.section_heading,
                    locator=excluded.locator,
                    extraction=excluded.extraction,
                    origin=excluded.origin,
                    curation_status=excluded.curation_status,
                    validation_status=excluded.validation_status
                """,
                rows,
            )
            connection.commit()
        finally:
            connection.close()
        return len(rows)

    @staticmethod
    def _where(
        *,
        cwe_ids: Sequence[str] = (),
        family: str | None = None,
        technology: str | None = None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if cwe_ids:
            placeholders = ", ".join("?" for _ in cwe_ids)
            clauses.append(f"cwe_id IN ({placeholders})")
            parameters.extend(cwe_ids)
        if family:
            clauses.append("family_key = ?")
            parameters.append(family)
        if technology:
            clauses.append("technology = ?")
            parameters.append(technology)
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", parameters

    @staticmethod
    def _item(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["payload_id"],
            "payload_id": row["payload_id"],
            "cwe_id": row["cwe_id"],
            "value": row["value"],
            "payload_digest": row["payload_digest"],
            "family_key": row["family_key"],
            "family_name": row["family_name"],
            "technology": row["technology"],
            "source_file": row["source_file"],
            "source_url": row["source_url"],
            "source_revision": row["source_revision"],
            "source_kind": row["source_kind"],
            "source_snapshot_digest": row["source_snapshot_digest"],
            "section_heading": row["section_heading"],
            "locator": row["locator"],
            "extraction": row["extraction"],
            "origin": row["origin"],
            "curation_status": row["curation_status"],
            "validation_status": row["validation_status"],
        }

    def query(
        self,
        *,
        cwe_ids: Sequence[str] = (),
        family: str | None = None,
        technology: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Return a deterministic page and aggregate family summaries."""

        if limit < 1 or limit > MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
        if offset < 0:
            raise ValueError("offset must be non-negative")
        where, parameters = self._where(
            cwe_ids=tuple(cwe_ids), family=family, technology=technology
        )
        connection = self._connect()
        try:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM patt_payloads{where}", parameters
                ).fetchone()[0]
            )
            rows = connection.execute(
                "SELECT * FROM patt_payloads"
                f"{where} ORDER BY family_key, technology, payload_id "
                "LIMIT ? OFFSET ?",
                [*parameters, limit, offset],
            ).fetchall()
            summary_rows = connection.execute(
                "SELECT family_key, family_name, COUNT(*) AS payload_count, "
                "GROUP_CONCAT(DISTINCT technology) AS technologies "
                f"FROM patt_payloads{where} GROUP BY family_key, family_name "
                "ORDER BY family_key",
                parameters,
            ).fetchall()
        finally:
            connection.close()
        families = []
        for row in summary_rows:
            technologies = sorted(
                item for item in (row["technologies"] or "").split(",") if item
            )
            families.append(
                {
                    "family_key": row["family_key"],
                    "family_name": row["family_name"],
                    "payload_count": int(row["payload_count"]),
                    "technologies": technologies,
                }
            )
        return {
            "payloads": [self._item(row) for row in rows],
            "families": families,
            "total": total,
            "limit": limit,
            "offset": offset,
            "truncated": offset + len(rows) < total,
        }

    def family_inventory(self, *, cwe_ids: Sequence[str]) -> tuple[dict[str, Any], ...]:
        """Return family counts, technologies, and source identities without payload text."""
        if not cwe_ids:
            return ()
        where, parameters = self._where(cwe_ids=tuple(cwe_ids))
        connection = self._connect()
        try:
            family_rows = connection.execute(
                "SELECT cwe_id, family_key, family_name, COUNT(*) AS payload_count "
                f"FROM patt_payloads{where} "
                "GROUP BY cwe_id, family_key, family_name "
                "ORDER BY cwe_id, family_key, family_name",
                parameters,
            ).fetchall()
            source_rows = connection.execute(
                "SELECT DISTINCT cwe_id, family_key, technology, source_revision, "
                "source_snapshot_digest "
                f"FROM patt_payloads{where} "
                "ORDER BY cwe_id, family_key, technology, source_revision, source_snapshot_digest",
                parameters,
            ).fetchall()
        finally:
            connection.close()

        source_refs: dict[tuple[str, str], dict[str, set[str]]] = {}
        for row in source_rows:
            key = (str(row["cwe_id"]), str(row["family_key"]))
            refs = source_refs.setdefault(
                key,
                {
                    "technologies": set(),
                    "source_revisions": set(),
                    "source_snapshot_digests": set(),
                },
            )
            for column, bucket in (
                ("technology", "technologies"),
                ("source_revision", "source_revisions"),
                ("source_snapshot_digest", "source_snapshot_digests"),
            ):
                value = row[column]
                if value:
                    refs[bucket].add(str(value))

        inventory: list[dict[str, Any]] = []
        for row in family_rows:
            key = (str(row["cwe_id"]), str(row["family_key"]))
            refs = source_refs.get(key, {})
            inventory.append({
                "cwe_id": key[0],
                "family_key": key[1],
                "family_name": str(row["family_name"]),
                "payload_count": int(row["payload_count"]),
                "technologies": sorted(refs.get("technologies", set())),
                "source_revisions": sorted(refs.get("source_revisions", set())),
                "source_snapshot_digests": sorted(refs.get("source_snapshot_digests", set())),
            })
        return tuple(inventory)


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "PATTIndex",
    "payload_digest",
]
