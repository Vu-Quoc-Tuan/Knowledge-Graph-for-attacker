"""Snapshot the official CAPEC catalog and XSD while pinning its parsed release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import requests

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

from ckg.ingestion.capec.client import CAPEC_CATALOG_URL, CAPEC_SCHEMA_URL, root_version
from ckg.provenance.store import SnapshotStore


def _fetch(url: str) -> bytes:
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    return response.content


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", default="3.9")
    parser.add_argument("--snapshot-root", default="registry/upstream_snapshots")
    parser.add_argument("--catalog-url", default=CAPEC_CATALOG_URL)
    parser.add_argument("--schema-url", default=CAPEC_SCHEMA_URL)
    args = parser.parse_args()

    catalog = _fetch(args.catalog_url)
    actual_release = root_version(catalog)
    if actual_release != args.release:
        raise ValueError(f"CAPEC catalog release mismatch: expected {args.release}, got {actual_release}")
    schema = _fetch(args.schema_url)
    store = SnapshotStore(args.snapshot_root)
    print(json.dumps({
        "catalog_url": args.catalog_url,
        "catalog_digest": store.put(catalog),
        "schema_url": args.schema_url,
        "schema_digest": store.put(schema),
        "release": actual_release,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
