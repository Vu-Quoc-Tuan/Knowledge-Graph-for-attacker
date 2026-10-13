"""Snapshot one pinned official CWE catalog and its matching XSD."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import requests

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

from ckg.ingestion.cwe.client import catalog_zip_url, extract_single_xml, root_version, schema_url
from ckg.provenance.store import SnapshotStore


def _fetch(url: str) -> bytes:
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    return response.content


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", default="4.20")
    parser.add_argument("--schema-version", default="7.3")
    parser.add_argument("--snapshot-root", default="registry/upstream_snapshots")
    parser.add_argument("--catalog-url")
    parser.add_argument("--schema-url")
    args = parser.parse_args()

    catalog_url = args.catalog_url or catalog_zip_url(args.release)
    catalog_zip = _fetch(catalog_url)
    catalog_xml = extract_single_xml(catalog_zip)
    actual_release = root_version(catalog_xml)
    if actual_release != args.release:
        raise ValueError(f"CWE catalog release mismatch: expected {args.release}, got {actual_release}")
    xsd_url = args.schema_url or schema_url(args.schema_version)
    xsd = _fetch(xsd_url)
    store = SnapshotStore(args.snapshot_root)
    print(json.dumps({
        "catalog_url": catalog_url,
        "catalog_zip_digest": store.put(catalog_zip),
        "catalog_xml_digest": store.put(catalog_xml),
        "schema_url": xsd_url,
        "schema_digest": store.put(xsd),
        "release": actual_release,
        "schema_version": args.schema_version,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
