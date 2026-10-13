"""Snapshot and import OWASP WSTG markdown cases into the knowledge graph."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

import requests

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

from ckg.graph.memory import InMemoryGraphRepository
from ckg.ingestion.digests import sha256_digest
from ckg.ingestion.wstg.importer import import_wstg_case
from ckg.provenance.store import SnapshotStore

DEFAULT_WSTG_URL = (
    "https://raw.githubusercontent.com/OWASP/wstg/master/"
    "document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/"
    "07-Testing_for_XML_Injection.md"
)


def _fetch(url: str, timeout: float = 60.0) -> bytes:
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.content


def main() -> int:
    parser = argparse.ArgumentParser(description="Snapshot and import an OWASP WSTG markdown case.")
    parser.add_argument("--url", default=DEFAULT_WSTG_URL, help="URL to raw WSTG markdown document")
    parser.add_argument("--file", help="Path to local WSTG markdown file instead of fetching from URL")
    parser.add_argument("--wstg-id", default="WSTG-INPV-07", help="WSTG checklist test identifier")
    parser.add_argument("--title", default="Testing for XML Injection", help="Title of the test case")
    parser.add_argument("--release", default="v4.2", help="Source release or pinned tag")
    parser.add_argument("--snapshot-root", default="registry/upstream_snapshots", help="Path to snapshot store")
    parser.add_argument(
        "--mapping-path",
        default=str(REPOSITORY_ROOT / "datasets/mappings/technique_aliases.yaml"),
        help="Path to technique alias mapping YAML",
    )
    parser.add_argument(
        "--target-cwes",
        default="CWE-611",
        help="Comma-separated explicit target CWE IDs",
    )
    parser.add_argument("--dry-run", action="store_true", help="Parse and validate without live persistence")
    args = parser.parse_args()

    if args.file:
        source_bytes = Path(args.file).read_bytes()
        source_url = f"file://{Path(args.file).resolve()}"
    else:
        source_bytes = _fetch(args.url)
        source_url = args.url

    store = SnapshotStore(args.snapshot_root)
    digest = store.put(source_bytes)
    markdown = source_bytes.decode("utf-8", errors="replace")

    target_cwe_ids = tuple(cwe.strip() for cwe in args.target_cwes.split(",") if cwe.strip())
    repository = InMemoryGraphRepository()
    report = import_wstg_case(
        repository,
        wstg_id=args.wstg_id,
        title=args.title,
        markdown=markdown,
        source_release=args.release,
        source_snapshot_digest=digest,
        source_url=source_url,
        retrieved_at=datetime.now(timezone.utc),
        mapping_path=args.mapping_path,
        target_cwe_ids=target_cwe_ids,
    )

    result = {
        "wstg_id": report.wstg_id,
        "title": args.title,
        "source_url": source_url,
        "source_release": args.release,
        "snapshot_digest": digest,
        "strategy_count": report.strategy_count,
        "technique_count": report.technique_count,
        "channel_count": report.channel_count,
        "oracle_count": report.oracle_count,
        "input_surface_count": report.input_surface_count,
        "target_cwe_count": report.target_cwe_count,
        "unresolved_cwe_ids": list(report.unresolved_cwe_ids),
        "node_count": len(repository.nodes()),
        "edge_count": len(repository.edges()),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
