"""Offline, repeatable audit of the v1 registry -> v2 assertion migration."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

from ckg.graph.memory import InMemoryGraphRepository
from ckg.ingestion.cwe.importer import import_cwe_catalog
from ckg.ingestion.cwe.parser import parse_cwe_catalog
from ckg.migration.legacy_registry import migrate_legacy_vulnerability_registry
from ckg.migration.legacy_vulnerability_events import migrate_legacy_vulnerability_events
from ckg.provenance.store import SnapshotStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return non-zero when migration diagnostics are present",
    )
    args = parser.parse_args(argv)
    mapping = yaml.safe_load((REPOSITORY_ROOT / "datasets/mappings/canonical_catalogs.yaml").read_text())
    cwe = mapping["catalogs"]["cwe"]
    store = SnapshotStore(REPOSITORY_ROOT / "registry/upstream_snapshots")
    repository = InMemoryGraphRepository()
    import_cwe_catalog(
        repository,
        parse_cwe_catalog(
            store.read(cwe["catalog_xml_digest"]),
            source_snapshot_digest=cwe["catalog_xml_digest"],
            retrieved_at=datetime.fromisoformat(cwe["replay_recorded_at"].replace("Z", "+00:00")),
            source_url=cwe["catalog_url"],
        ),
    )
    registry_path = REPOSITORY_ROOT / "registry/vulnerabilities.yaml"
    report = migrate_legacy_vulnerability_registry(
        repository,
        registry_path,
        snapshot_object_dir=store.objects,
    )
    if report.target_schema != "ckg-v2":
        raise ValueError("legacy registry migration did not target ckg-v2")
    retry_report = migrate_legacy_vulnerability_registry(
        repository,
        registry_path,
        snapshot_object_dir=store.objects,
    )
    if retry_report != report:
        raise ValueError("legacy registry retry changed migration report")
    events = migrate_legacy_vulnerability_events(
        repository,
        REPOSITORY_ROOT / "registry/vulnerability_event_log.jsonl",
    )
    if events.target_schema != "ckg-v2":
        raise ValueError("legacy event migration did not target ckg-v2")
    diagnostic_counts = {
        "registry": dict(Counter(code for code, _, _ in report.diagnostics)),
        "events": dict(Counter(code for code, _, _ in events.diagnostics)),
    }
    has_diagnostics = any(diagnostic_counts.values())
    print(
        json.dumps(
            {
                "status": "PASS" if not has_diagnostics else "PASS_WITH_DIAGNOSTICS",
                "promotion_allowed": not has_diagnostics,
                "diagnostic_counts": diagnostic_counts,
                "registry": report.__dict__,
                "events": events.__dict__,
                "graph": {"nodes": len(repository.nodes()), "edges": len(repository.edges())},
                "retry": "idempotent",
            },
            sort_keys=True,
        )
    )
    return 2 if args.strict and has_diagnostics else 0


if __name__ == "__main__":
    raise SystemExit(main())
