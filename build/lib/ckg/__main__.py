"""Installed-package entry point for the v2 CKG service."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys

import yaml

from ckg.api.main import make_handler
from ckg.application.analyze_vulnerability import analyze_cve
from ckg.application.build_initial_graph import build_initial_graph
from ckg.application.ingest_cve import ingest_structured_source
from ckg.application.ingest_cwe import ingest_cwe_catalog
from ckg.application.ingest_patt import ingest_patt_sources
from ckg.domain.entities.observation import ExecutionObservation, ObservationResult
from ckg.evolution.cooccurrence import mine_cooccurrence
from ckg.evolution.cwe_profiler import rebuild_cwe_profiles
from ckg.feedback.evidence_quality import ObservationQuality
from ckg.feedback.updater import process_observation
from ckg.graph.models import GraphNode
from ckg.graph.memory import InMemoryGraphRepository
from ckg.graph.ports import GraphRepository
from ckg.ingestion.cve.cve_services_client import CVE_SERVICES_RECORD_URL, fetch_record
from ckg.ingestion.cve.nvd_client import NVD_CVE_API_URL, fetch_cve
from ckg.ingestion.patt.payload_importer import PATTSourceFile
from ckg.provenance.store import SnapshotStore
from ckg.config.env import load_env
from ckg.config.settings import NEO4J_DEFAULT_URI, Settings
from ckg.runtime import create_application, create_repository


load_env()


def _get_repository(args: argparse.Namespace) -> GraphRepository:
    load_env()
    return create_repository(
        memory=bool(getattr(args, "memory", False) or getattr(args, "dry_run", False)),
        uri=getattr(args, "neo4j_uri", None),
        user=getattr(args, "neo4j_user", None),
        password=getattr(args, "neo4j_password", None),
        snapshot_root=getattr(args, "snapshot_root", None),
    )


def _add_common_connection_args(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--neo4j-uri",
        default=os.environ.get("NEO4J_URI", NEO4J_DEFAULT_URI),
        help="Neo4j connection URI (env: NEO4J_URI)",
    )
    subparser.add_argument(
        "--neo4j-user",
        default=os.environ.get("NEO4J_USER", "neo4j"),
        help="Neo4j username (env: NEO4J_USER)",
    )
    subparser.add_argument(
        "--neo4j-password",
        default=os.environ.get("NEO4J_PASSWORD", "change-me-please"),
        help="Neo4j password (env: NEO4J_PASSWORD)",
    )
    subparser.add_argument(
        "--snapshot-root",
        default=os.environ.get("SOURCE_SNAPSHOT_ROOT", "registry/upstream_snapshots"),
        help="Snapshot storage root directory (env: SOURCE_SNAPSHOT_ROOT)",
    )
    subparser.add_argument(
        "--memory",
        action="store_true",
        help="Use in-memory repository (for testing or isolated verification)",
    )


def _serve(args: argparse.Namespace) -> int:
    repository = _get_repository(args)
    try:
        schema_path = Path(__file__).parent / "graph" / "neo4j" / "schema.cypher"
        if schema_path.exists() and hasattr(repository, "apply_schema"):
            repository.apply_schema(str(schema_path))
        snapshot_root = args.snapshot_root
        app = create_application(repository, snapshot_root=snapshot_root)
        server = ThreadingHTTPServer(
            (args.host, args.port),
            make_handler(app, max_request_body_bytes=Settings.from_env().max_request_body_bytes),
        )
        ui_url = f"http://{args.host}:{args.port}/ui/v2"
        backend_type = "In-Memory RAM" if getattr(args, "memory", False) else "Neo4j Database"
        print("==========================================================================")
        print(f"  [✓] CKG Server đã khởi động thành công! ({backend_type})")
        print(f"  👉 Truy cập Web UI tại: {ui_url}")
        print(f"  👉 API Endpoint mẫu:    http://{args.host}:{args.port}/cwes/CWE-79/scenarios")
        print("  (Server đang chạy lắng nghe requests. Nhấn Ctrl+C để dừng)")
        print("==========================================================================")
        sys.stdout.flush()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Đã nhận tín hiệu dừng. Đang tắt CKG Server...")
        finally:
            server.server_close()
    finally:
        if hasattr(repository, "close"):
            repository.close()
    return 0


def _analyze(args: argparse.Namespace) -> int:
    vulnerability_id = args.vulnerability_id or args.vuln_id
    if not vulnerability_id:
        raise ValueError("vulnerability identifier is required (positional or --vuln-id)")
    # The current analyze use case materializes extracted assertions and
    # scenarios.  Treating a historical cutoff as `retrieved_at` would both
    # leak current graph state into the decision and backdate new writes.
    if args.as_of:
        raise ValueError(
            "--as-of analysis is not available until the read-only temporal analysis path is configured; "
            "use a temporal query endpoint instead"
        )
    repository = _get_repository(args)
    try:
        retrieved_at = datetime.now(timezone.utc)
        analysis = analyze_cve(
            repository,
            vulnerability_id,
            retrieved_at=retrieved_at,
            use_model=args.use_model,
        )
        data = asdict(analysis)
        if args.format == "yaml":
            print(yaml.safe_dump(data, sort_keys=False))
        else:
            print(json.dumps(data, indent=2, sort_keys=True, default=str))
    finally:
        if hasattr(repository, "close"):
            repository.close()
    return 0


def _ingest(args: argparse.Namespace) -> int:
    snapshot_root = args.snapshot_root
    repository = _get_repository(args)
    try:
        retrieved_at = datetime.fromisoformat(args.retrieved_at) if args.retrieved_at else datetime.now(timezone.utc)
        targets = [value for value in (args.cve, args.cwe, args.patt_cwe) if value]
        if len(targets) != 1:
            raise ValueError("exactly one of --cve, --cwe, or --patt-cwe is required")
        if args.patt_cwe:
            if not args.file:
                raise ValueError("--file is required when ingesting a PATT payload manifest")
            try:
                manifest = json.loads(Path(args.file).read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"PATT manifest must be valid UTF-8 JSON: {exc}") from exc
            raw_sources = manifest.get("sources") if isinstance(manifest, dict) else None
            if not isinstance(raw_sources, list) or not raw_sources:
                raise ValueError("PATT manifest requires a non-empty sources list")
            sources: list[PATTSourceFile] = []
            for index, raw_source in enumerate(raw_sources):
                if not isinstance(raw_source, dict):
                    raise ValueError(f"PATT source {index} must be an object")
                required = ("source_file", "source_url", "content")
                missing = [name for name in required if not isinstance(raw_source.get(name), str) or not raw_source[name].strip()]
                revision = raw_source.get("source_revision") or args.source_revision
                if not isinstance(revision, str) or not revision.strip():
                    missing.append("source_revision")
                if missing:
                    raise ValueError(f"PATT source {index} missing required fields: {', '.join(sorted(set(missing)))}")
                kind = raw_source.get("kind", "markdown")
                technology = raw_source.get("technology")
                if not isinstance(kind, str) or kind not in {"markdown", "wordlist"}:
                    raise ValueError(f"PATT source {index} has unsupported kind: {kind!r}")
                if technology is not None and not isinstance(technology, str):
                    raise ValueError(f"PATT source {index} technology must be a string when supplied")
                sources.append(PATTSourceFile(
                    source_file=raw_source["source_file"],
                    source_url=raw_source["source_url"],
                    source_revision=revision,
                    content=raw_source["content"],
                    kind=kind,
                    technology=technology,
                ))
            report = ingest_patt_sources(
                repository,
                slice_cwe_id=args.patt_cwe,
                sources=tuple(sources),
                retrieved_at=retrieved_at,
                snapshot_root=snapshot_root,
                max_payloads_per_family=args.max_payloads_per_family or 400,
            )
            print(json.dumps(asdict(report), indent=2, sort_keys=True, default=str))
        elif args.cwe:
            if not args.file:
                raise ValueError("--file is required when ingesting CWE catalog")
            file_path = Path(args.file)
            raw_xml = file_path.read_bytes()
            digest = args.source_snapshot_digest
            if not digest:
                store = SnapshotStore(snapshot_root)
                digest = store.put(raw_xml)
            source_url = args.source_url or f"file://{file_path.resolve()}"
            import_rep, enrich_rep = ingest_cwe_catalog(
                repository,
                raw_xml=raw_xml,
                source_snapshot_digest=digest,
                retrieved_at=retrieved_at,
                source_url=source_url,
            )
            result = {
                "cwe": args.cwe,
                "snapshot_digest": digest,
                "import": asdict(import_rep),
                "enrichment": asdict(enrich_rep),
            }
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
        elif args.cve:
            if args.file:
                raw_bytes = Path(args.file).read_bytes()
                source_url = args.source_url or f"file://{Path(args.file).resolve()}"
            else:
                if args.source_kind == "cve_services":
                    raw_bytes = fetch_record(args.cve)
                    source_url = args.source_url or CVE_SERVICES_RECORD_URL.format(cve_id=args.cve)
                elif args.source_kind == "nvd":
                    raw_bytes = fetch_cve(args.cve, api_key=args.nvd_api_key)
                    source_url = args.source_url or f"{NVD_CVE_API_URL}?cveId={args.cve}"
                else:
                    raise ValueError(f"unsupported source kind: {args.source_kind}")

            res = ingest_structured_source(
                repository,
                source_kind=args.source_kind,
                raw_payload=raw_bytes,
                source_url=source_url,
                retrieved_at=retrieved_at,
                snapshot_root=snapshot_root,
            )
            result = {
                "cve": args.cve,
                "snapshot_digest": res.snapshot_digest,
                "report": asdict(res.report),
                "analyses": [asdict(item) for item in res.analyses],
            }
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
    finally:
        if hasattr(repository, "close"):
            repository.close()
    return 0


def _feedback(args: argparse.Namespace) -> int:
    repository = _get_repository(args)
    try:
        if args.file:
            payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
        else:
            if not args.observation_id or not args.scenario_id or not args.environment_id or not args.result:
                raise ValueError("--observation-id, --scenario-id, --environment-id, and --result are required")
            evidence_ids = (
                [x.strip() for x in args.evidence_ids.split(",") if x.strip()]
                if args.evidence_ids
                else [f"EVID-{args.observation_id}"]
            )
            evidence_digests = (
                [x.strip() for x in args.evidence_digests.split(",") if x.strip()]
                if args.evidence_digests
                else ["sha256:" + "0" * 64]
            )
            payload = {
                "observation_id": args.observation_id,
                "scenario_id": args.scenario_id,
                "scenario_revision": args.scenario_revision,
                "environment": {
                    "environment_id": args.environment_id,
                    "target_platform": args.target_platform or "unknown",
                },
                "result": args.result,
                "scope_key": args.scope_key or args.scenario_id,
                "observed_at": args.observed_at or datetime.now(timezone.utc).isoformat(),
                "evidence_ids": evidence_ids,
                "evidence_digests": evidence_digests,
                "quality": {
                    "oracle_observable": args.oracle_observable,
                    "environment_complete": args.environment_complete,
                    "source_evidence_present": args.source_evidence_present,
                },
            }

        environment = payload["environment"]
        env_id = environment["environment_id"]
        scen_id = payload["scenario_id"]
        existing_nodes = {n.node_id for n in repository.nodes()}
        if scen_id not in existing_nodes:
            raise ValueError("feedback scenario must already exist")
        missing_evidence = set(payload.get("evidence_ids", ())) - existing_nodes
        if missing_evidence:
            raise ValueError("feedback evidence must already exist as a verified execution receipt")
        # The environment snapshot is the one input allowed to be introduced
        # with an observation.  Scenario and evidence identities must predate
        # feedback so callers cannot manufacture their own authorization.
        if env_id not in existing_nodes:
            repository.atomic_write(nodes=[GraphNode(label="Environment", node_id=env_id, props=environment)], edges=[])

        obs_time = datetime.fromisoformat(payload["observed_at"]) if isinstance(payload.get("observed_at"), str) else datetime.now(timezone.utc)
        observation = ExecutionObservation(
            observation_id=payload["observation_id"],
            scenario_id=payload["scenario_id"],
            scenario_revision=payload.get("scenario_revision", 1),
            environment_id=env_id,
            result=ObservationResult(payload["result"]),
            observed_at=obs_time,
            evidence_ids=tuple(payload.get("evidence_ids", ())),
            evidence_digests=tuple(payload.get("evidence_digests", ())),
        )
        quality_data = payload.get("quality", {})
        quality = ObservationQuality(
            oracle_observable=bool(quality_data.get("oracle_observable", True)),
            environment_complete=bool(quality_data.get("environment_complete", True)),
            source_evidence_present=bool(quality_data.get("source_evidence_present", True)),
        )
        result = process_observation(
            repository,
            observation=observation,
            scope_key=payload.get("scope_key", payload["scenario_id"]),
            quality=quality,
        )
        out = {
            "posterior_id": result.posterior_id,
            "alpha": result.posterior.alpha,
            "beta": result.posterior.beta,
            "applied_weight": result.applied_weight,
            "deduplicated": result.deduplicated,
        }
        print(json.dumps(out, indent=2, sort_keys=True))
    finally:
        if hasattr(repository, "close"):
            repository.close()
    return 0


def _build(args: argparse.Namespace) -> int:
    repository = _get_repository(args)
    staging: GraphRepository | None = None
    try:
        if getattr(args, "reset", False) and not getattr(args, "memory", False) and not getattr(args, "dry_run", False):
            staging = InMemoryGraphRepository()
            build_repository = staging
        else:
            build_repository = repository

        schema_path = Path(__file__).parent / "graph" / "neo4j" / "schema.cypher"
        if schema_path.exists() and hasattr(repository, "apply_schema"):
            repository.apply_schema(str(schema_path))

        mapping_path = Path(args.mapping_path) if getattr(args, "mapping_path", None) else None
        if not mapping_path or not mapping_path.exists():
            candidates = [
                Path("datasets/mappings/canonical_catalogs.yaml"),
                Path(__file__).resolve().parents[2] / "datasets/mappings/canonical_catalogs.yaml",
            ]
            for cand in candidates:
                if cand.exists():
                    mapping_path = cand
                    break

        if not mapping_path or not mapping_path.exists():
            raise FileNotFoundError("canonical_catalogs.yaml not found")

        mapping = yaml.safe_load(mapping_path.read_text(encoding="utf-8"))
        catalogs = mapping["catalogs"]
        store = SnapshotStore(args.snapshot_root)
        cwe_cfg = catalogs["cwe"]
        capec_cfg = catalogs["capec"]
        cwe_xml = store.read(cwe_cfg["catalog_xml_digest"])
        capec_xml = store.read(capec_cfg["catalog_digest"])

        report = build_initial_graph(
            build_repository,
            cwe_xml=cwe_xml,
            cwe_snapshot_digest=cwe_cfg["catalog_xml_digest"],
            cwe_retrieved_at=datetime.fromisoformat(cwe_cfg["replay_recorded_at"].replace("Z", "+00:00")),
            cwe_source_url=cwe_cfg["catalog_url"],
            capec_xml=capec_xml,
            capec_snapshot_digest=capec_cfg["catalog_digest"],
            capec_retrieved_at=datetime.fromisoformat(capec_cfg["replay_recorded_at"].replace("Z", "+00:00")),
            capec_source_url=capec_cfg["catalog_url"],
        )
        vuln_registry_path = Path("registry/vulnerabilities.yaml")
        if not vuln_registry_path.exists():
            vuln_registry_path = Path(__file__).resolve().parents[2] / "registry" / "vulnerabilities.yaml"
        if vuln_registry_path.exists():
            from ckg.migration.legacy_registry import migrate_legacy_vulnerability_registry
            migrate_legacy_vulnerability_registry(
                build_repository,
                vuln_registry_path,
                snapshot_object_dir=store.objects,
            )
        if staging is not None:
            repository.replace_all(nodes=staging.nodes(), edges=staging.edges())
        result = {
            "cwe": asdict(report.cwe),
            "capec": asdict(report.capec),
            "node_count": len(repository.nodes()),
            "edge_count": len(repository.edges()),
        }
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    finally:
        if hasattr(repository, "close"):
            repository.close()
        if staging is not None and hasattr(staging, "close"):
            staging.close()
    return 0


def _rebuild(args: argparse.Namespace) -> int:
    repository = _get_repository(args)
    try:
        profiles_report = rebuild_cwe_profiles(repository)
        cooc_report = mine_cooccurrence(repository)
        out = {
            "profiles": asdict(profiles_report),
            "cooccurrence": asdict(cooc_report),
        }
        print(json.dumps(out, indent=2, sort_keys=True))
    finally:
        if hasattr(repository, "close"):
            repository.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ckg", description="Evolving vulnerability CKG Module-1 service and CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 0. build
    build = subparsers.add_parser(
        "build",
        help="build initial canonical CWE and CAPEC knowledge graph from verified snapshots",
    )
    build.add_argument("--mapping-path", help="Path to canonical_catalogs.yaml")
    build.add_argument(
        "--dry-run",
        action="store_true",
        help="build only in memory; compatibility alias for --memory",
    )
    build.add_argument(
        "--reset",
        action="store_true",
        help="stage a complete v2 graph and replace the target Neo4j graph atomically",
    )
    _add_common_connection_args(build)
    build.set_defaults(handler=_build)

    # 1. serve
    serve = subparsers.add_parser("serve", help="serve the Module-1 HTTP API backed by Neo4j")
    _add_common_connection_args(serve)
    serve.add_argument("--host", default="127.0.0.1", help="HTTP server listen host")
    serve.add_argument("--port", type=int, default=8088, help="HTTP server listen port")
    serve.set_defaults(handler=_serve)

    # 2. analyze
    analyze = subparsers.add_parser("analyze", help="analyze a CVE and output the Section 55 semantic analysis contract")
    analyze.add_argument("vulnerability_id", nargs="?", help="Vulnerability identifier (e.g. CVE-2024-44541)")
    analyze.add_argument("--vuln-id", help="Alternative flag for vulnerability identifier")
    analyze.add_argument("--as-of", help="Point-in-time ISO timestamp for temporal queries")
    analyze.add_argument("--format", choices=["json", "yaml"], default="json", help="Output format (json or yaml)")
    analyze.add_argument("--use-model", action="store_true", help="Enable model-backed facet extraction")
    _add_common_connection_args(analyze)
    analyze.set_defaults(handler=_analyze)

    # 3. ingest
    ingest = subparsers.add_parser("ingest", help="ingest structured records, CWE catalog, or explicit PATT reference payloads")
    ingest.add_argument("--cve", help="CVE identifier to ingest")
    ingest.add_argument("--cwe", help="CWE identifier or catalog indicator to ingest")
    ingest.add_argument("--patt-cwe", help="Import one curated PATT reference-payload slice for this existing CWE")
    ingest.add_argument("--source-kind", choices=["cve_services", "nvd", "ghsa"], default="cve_services", help="Source provider kind")
    ingest.add_argument("--file", help="Path to local JSON or XML payload file")
    ingest.add_argument("--source-url", help="Origin source URL for provenance")
    ingest.add_argument("--source-snapshot-digest", help="Optional verified SHA-256 snapshot digest")
    ingest.add_argument("--source-revision", help="Immutable PATT source revision used when a manifest source omits it")
    ingest.add_argument("--max-payloads-per-family", type=int, help="Maximum PATT references retained per family and source")
    ingest.add_argument("--nvd-api-key", help="NVD API key for NVD source fetches")
    ingest.add_argument("--retrieved-at", help="Retrieval ISO timestamp")
    _add_common_connection_args(ingest)
    ingest.set_defaults(handler=_ingest)

    # 4. feedback
    feedback = subparsers.add_parser("feedback", help="record execution feedback and update Bayesian posteriors")
    feedback.add_argument("--file", help="Path to JSON file containing complete observation payload")
    feedback.add_argument("--observation-id", help="Observation identifier")
    feedback.add_argument("--scenario-id", help="Target scenario identifier")
    feedback.add_argument("--scenario-revision", type=int, default=1, help="Scenario revision")
    feedback.add_argument("--environment-id", help="Execution environment identifier")
    feedback.add_argument("--target-platform", default="linux", help="Target environment platform")
    feedback.add_argument("--result", choices=["REPRODUCED", "NO_SIGNAL", "BLOCKED", "NOT_APPLICABLE", "INCONCLUSIVE", "ERROR"], help="Execution outcome")
    feedback.add_argument("--scope-key", help="Bayesian update scope key (e.g. weakness ID)")
    feedback.add_argument("--evidence-ids", help="Comma-separated evidence IDs supporting this observation")
    feedback.add_argument("--evidence-digests", help="Comma-separated evidence SHA-256 digests")
    feedback.add_argument("--observed-at", help="Observation ISO timestamp")
    feedback.add_argument("--oracle-observable", action=argparse.BooleanOptionalAction, default=True, help="Oracle observable status")
    feedback.add_argument("--environment-complete", action=argparse.BooleanOptionalAction, default=True, help="Environment completeness status")
    feedback.add_argument("--source-evidence-present", action=argparse.BooleanOptionalAction, default=True, help="Source evidence presence status")
    _add_common_connection_args(feedback)
    feedback.set_defaults(handler=_feedback)

    # 5. rebuild
    rebuild = subparsers.add_parser("rebuild", help="rebuild learned CWE context profiles and co-occurrence graphs")
    _add_common_connection_args(rebuild)
    rebuild.set_defaults(handler=_rebuild)

    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
