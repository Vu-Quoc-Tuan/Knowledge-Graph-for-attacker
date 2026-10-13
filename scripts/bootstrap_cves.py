"""Snapshot and import CVE records from CVE Services or NVD API into the knowledge graph."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from ckg.graph.memory import InMemoryGraphRepository
from ckg.ingestion.cve.cve_services_client import CVE_SERVICES_RECORD_URL, fetch_record
from ckg.ingestion.cve.importer import import_structured_records
from ckg.ingestion.cve.nvd_client import NVD_CVE_API_URL, fetch_cve
from ckg.ingestion.cve.parser import parse_cve_services_record, parse_nvd_response
from ckg.provenance.store import SnapshotStore

DEFAULT_CVES = "CVE-2024-21626,CVE-2021-44228"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Snapshot and import CVE records from CVE Services or NVD API 2.0."
    )
    parser.add_argument(
        "--cve-ids",
        default=DEFAULT_CVES,
        help="Comma-separated list of CVE IDs to fetch and import",
    )
    parser.add_argument(
        "--source",
        choices=["cve_services", "nvd"],
        default="cve_services",
        help="Upstream data source API (default: cve_services)",
    )
    parser.add_argument(
        "--file",
        help="Path to local JSON file containing CVE record or NVD response instead of fetching",
    )
    parser.add_argument(
        "--nvd-api-key",
        help="NVD API key (optional, increases rate limit)",
    )
    parser.add_argument(
        "--snapshot-root",
        default="registry/upstream_snapshots",
        help="Path to snapshot store",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and validate without live persistence",
    )
    parser.add_argument(
        "--neo4j",
        action="store_true",
        help="Write imported records into Neo4j graph repository instead of memory",
    )
    args = parser.parse_args()

    store = SnapshotStore(args.snapshot_root)
    if args.neo4j and not args.dry_run:
        from ckg.config.settings import Settings
        from ckg.graph.neo4j.driver import Neo4jGraphRepository
        settings = Settings.from_env()
        repository = Neo4jGraphRepository(
            settings.neo4j_uri,
            settings.neo4j_user,
            settings.neo4j_password,
        )
    else:
        repository = InMemoryGraphRepository()
    results = []

    if args.file:
        file_path = Path(args.file)
        raw_bytes = file_path.read_bytes()
        digest = store.put(raw_bytes)
        source_url = f"file://{file_path.resolve()}"
        payload = json.loads(raw_bytes)

        if "cveMetadata" in payload:
            records = (parse_cve_services_record(payload, source_url=source_url),)
        elif "vulnerabilities" in payload:
            records = parse_nvd_response(payload, source_url=source_url)
        else:
            raise ValueError(f"unrecognized CVE record format in {args.file}")

        report = import_structured_records(
            repository,
            records,
            source_snapshot_digest=digest,
            retrieved_at=datetime.now(timezone.utc),
        )
        results.append({
            "source": "file",
            "source_url": source_url,
            "snapshot_digest": digest,
            "record_count": report.source_record_count,
            "vulnerability_count": report.vulnerability_count,
            "assertion_count": report.weakness_assertion_count,
            "unresolved_cwe_ids": list(report.unresolved_cwe_ids),
        })
    else:
        cve_ids = [cve.strip() for cve in args.cve_ids.split(",") if cve.strip()]
        for cve_id in cve_ids:
            if args.source == "cve_services":
                raw_bytes = fetch_record(cve_id)
                source_url = CVE_SERVICES_RECORD_URL.format(cve_id=cve_id)
                digest = store.put(raw_bytes)
                payload = json.loads(raw_bytes)
                records = (parse_cve_services_record(payload, source_url=source_url),)
            else:
                raw_bytes = fetch_cve(cve_id, api_key=args.nvd_api_key)
                source_url = f"{NVD_CVE_API_URL}?cveId={cve_id}"
                digest = store.put(raw_bytes)
                payload = json.loads(raw_bytes)
                records = parse_nvd_response(payload, source_url=source_url)

            report = import_structured_records(
                repository,
                records,
                source_snapshot_digest=digest,
                retrieved_at=datetime.now(timezone.utc),
            )
            results.append({
                "cve_id": cve_id,
                "source": args.source,
                "source_url": source_url,
                "snapshot_digest": digest,
                "record_count": report.source_record_count,
                "vulnerability_count": report.vulnerability_count,
                "assertion_count": report.weakness_assertion_count,
                "unresolved_cwe_ids": list(report.unresolved_cwe_ids),
            })

    output = {
        "cves_processed": len(results),
        "results": results,
        "graph_node_count": len(repository.nodes()),
        "graph_edge_count": len(repository.edges()),
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    if hasattr(repository, "close"):
        repository.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
