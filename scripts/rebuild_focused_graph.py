"""Replace the active Neo4j projection with a focused ten-CWE experiment graph.

The command stages and validates the projection in memory, writes a local JSON
backup of the current v2 graph, then performs one atomic Neo4j replacement.
Source snapshots and registry files are never deleted.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

import requests

from ckg.application.focused_rebuild import (
    FOCUSED_CWE_IDS,
    PATT_NATIVE_CWE_IDS,
    FocusedProjectionReport,
    build_focused_projection,
    current_utc,
    validate_focused_projection,
)
from ckg.config.settings import Settings
from ckg.evolution.cooccurrence import mine_cooccurrence
from ckg.evolution.cwe_profiler import rebuild_cwe_profiles
from ckg.graph.memory import InMemoryGraphRepository
from ckg.graph.models import GraphEdge
from ckg.graph.neo4j.driver import Neo4jGraphRepository
from ckg.ingestion.patt.payload_importer import (
    PATTSourceFile,
    restore_patt_semantic_plane,
    slice_for_cwe,
)
from ckg.ingestion.patt.payload_index import PATTIndex
from ckg.application.ingest_patt import ingest_patt_sources
from ckg.ingestion.wstg.catalog import store_canonical_wstg_snapshots
from ckg.provenance.compact_details import (
    COMPACT_DETAILS_DB_NAME,
    CompactDetailStore,
    collect_compact_detail_records,
    is_compact_detail_node,
    merge_compact_detail_records,
)
from ckg.provenance.graph_compaction import compact_version_ranges
from ckg.provenance.store import SnapshotStore


DEFAULT_PATT_COMMIT = "3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a"
PATT_REPO = "swisskyrepo/PayloadsAllTheThings"
_PATT_TECH_ALIASES = {
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "mysql": "MySQL",
    "sql server": "MSSQL",
    "sql_server": "MSSQL",
    "mssql": "MSSQL",
    "oracle": "Oracle",
    "oraclesql": "Oracle",
    "oracle sql": "Oracle",
    "ms access": "MS Access",
    "ms_access": "MS Access",
    "sqlite": "SQLite",
    "python": "Python",
    "php": "PHP",
    "java": "Java",
    "javascript": "JavaScript",
    "ruby": "Ruby",
    "asp": "ASP",
    "elixir": "Elixir",
    "perl": "Perl",
    "dotnet": ".NET",
    "net": ".NET",
    "node": "Node.js",
    "nodejs": "Node.js",
}


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "ckg-focused-rebuild"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_get(session: requests.Session, url: str, **kwargs: object) -> requests.Response:
    response = session.get(url, **kwargs)
    if response.status_code == 401 and "Authorization" in session.headers:
        # PATT is public.  A stale local token must not block a reproducible
        # anonymous fetch, and its value must never be printed in diagnostics.
        session.headers.pop("Authorization", None)
        response = session.get(url, **kwargs)
    return response


def _github_json(session: requests.Session, path: str, commit: str) -> object:
    url = f"https://api.github.com/repos/{PATT_REPO}/contents/{quote(path, safe='/')}"
    response = _github_get(session, url, params={"ref": commit}, timeout=60)
    response.raise_for_status()
    return response.json()


def _raw_url(path: str, commit: str) -> str:
    return f"https://raw.githubusercontent.com/{PATT_REPO}/{commit}/{quote(path, safe='/')}"


def _normalize_patt_technology(filename: str) -> str | None:
    value = Path(filename).stem
    value = re.sub(r"^\d+(?:\.\d+)?-", "", value)
    for prefix in ("Testing_for_", "Testing_", "SQL_Injection_", "SQL Injection "):
        if value.lower().startswith(prefix.lower()):
            value = value[len(prefix):]
            break
    value = re.sub(r"\bInjection\b", "", value, flags=re.IGNORECASE)
    cleaned = re.sub(r"[\s_-]+", " ", value).strip().lower()
    for alias, canonical in _PATT_TECH_ALIASES.items():
        if cleaned == alias or cleaned.startswith(alias + " "):
            return canonical
    return None


def _fetch_patt_sources(
    *,
    cwe_id: str,
    commit: str,
    session: requests.Session,
) -> tuple[PATTSourceFile, ...]:
    slice_ = slice_for_cwe(cwe_id)
    listing = _github_json(session, slice_.patt_dir, commit)
    if not isinstance(listing, list):
        raise ValueError(f"PATT directory is not a listing: {slice_.patt_dir}")
    sources: list[PATTSourceFile] = []
    markdown_entries = [
        item for item in listing
        if isinstance(item, dict)
        and str(item.get("name", "")).lower().endswith(".md")
        and item.get("type") == "file"
    ]
    for item in sorted(markdown_entries, key=lambda value: str(value["name"])):
        path = str(item["path"])
        content = _github_get(session, _raw_url(path, commit), timeout=60)
        content.raise_for_status()
        technology = None
        if slice_.technology_from_filename:
            technology = _normalize_patt_technology(str(item["name"]))
        sources.append(
            PATTSourceFile(
                source_file=path,
                source_url=_raw_url(path, commit),
                source_revision=commit,
                content=content.text,
                kind="markdown",
                technology=technology,
            )
        )

    if slice_.intruder_dir and slice_.intruder_family is not None:
        intruder_path = f"{slice_.patt_dir}/{slice_.intruder_dir}"
        try:
            intruder_listing = _github_json(session, intruder_path, commit)
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                intruder_listing = []
            else:
                raise
        if not isinstance(intruder_listing, list):
            raise ValueError(f"PATT Intruder directory is not a listing: {intruder_path}")
        for item in sorted(
            (
                value for value in intruder_listing
                if isinstance(value, dict)
                and str(value.get("name", "")).lower().endswith(".txt")
                and value.get("type") == "file"
            ),
            key=lambda value: str(value["name"]),
        ):
            path = str(item["path"])
            content = _github_get(session, _raw_url(path, commit), timeout=60)
            content.raise_for_status()
            sources.append(
                PATTSourceFile(
                    source_file=path,
                    source_url=_raw_url(path, commit),
                    source_revision=commit,
                    content=content.text,
                    kind="wordlist",
                )
            )
    return tuple(sources)


def _backup_graph(root: Path, nodes: list, edges: list, *, patt_commit: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = root / f"neo4j-full-backup-{timestamp}.json"
    payload = {
        "format": "ckg-v2-focused-rebuild-backup",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "patt_commit_for_new_projection": patt_commit,
        "nodes": [node.model_dump(mode="json") for node in nodes],
        "edges": [edge.model_dump(mode="json") for edge in edges],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def _add_patt(
    repository: InMemoryGraphRepository,
    *,
    snapshot_root: str,
    commit: str,
    retrieved_at: datetime,
) -> dict[str, object]:
    session = requests.Session()
    session.headers.update(_github_headers())
    reports: list[dict[str, object]] = []
    for cwe_id in sorted(PATT_NATIVE_CWE_IDS):
        sources = _fetch_patt_sources(cwe_id=cwe_id, commit=commit, session=session)
        report = ingest_patt_sources(
            repository,
            slice_cwe_id=cwe_id,
            sources=sources,
            retrieved_at=retrieved_at,
            snapshot_root=snapshot_root,
            max_payloads_per_family=400,
        )
        reports.append(asdict(report))
    return {
        "commit": commit,
        "native_cwe_ids": sorted(PATT_NATIVE_CWE_IDS),
        "unsupported_exact_cwe_ids": sorted(FOCUSED_CWE_IDS - PATT_NATIVE_CWE_IDS),
        "reports": reports,
    }


def _deduplicate_technologies(repository: InMemoryGraphRepository) -> None:
    """Consolidate same-name technology nodes across independent PATT slices."""
    nodes = repository.nodes()
    edges = repository.edges()
    canonical: dict[str, str] = {}
    remap: dict[str, str] = {}
    for node in nodes:
        if node.label != "Technology":
            continue
        key = str(node.props.get("name", "")).strip().casefold()
        if not key:
            continue
        canonical_id = canonical.setdefault(key, node.node_id)
        if node.node_id != canonical_id:
            remap[node.node_id] = canonical_id
    if not remap:
        return
    kept_nodes = [node for node in nodes if node.node_id not in remap]
    rewritten_edges: list[GraphEdge] = []
    for edge in edges:
        rewritten_edges.append(
            GraphEdge(
                edge_id=edge.edge_id,
                edge_type=edge.edge_type,
                subject_id=remap.get(edge.subject_id, edge.subject_id),
                object_id=remap.get(edge.object_id, edge.object_id),
                props=edge.props,
            )
        )
    repository.replace_all(nodes=kept_nodes, edges=rewritten_edges)


def _validate_snapshot_objects(
    snapshot_root: str,
    nodes: list,
    edges: list[GraphEdge],
    *,
    extra_digests: set[str] | None = None,
) -> int:
    """Fail closed if the staged graph references an unavailable source object."""
    store = SnapshotStore(snapshot_root)
    digests: set[str] = set()
    for node in nodes:
        for key in ("source_snapshot_digest", "content_digest"):
            value = node.props.get(key)
            if isinstance(value, str) and value.startswith("sha256:"):
                digests.add(value)
    for edge in edges:
        value = edge.props.get("source_snapshot_digest")
        if isinstance(value, str) and value.startswith("sha256:"):
            digests.add(value)
    digests.update(extra_digests or set())
    for digest in sorted(digests):
        store.read(digest)
    return len(digests)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--patt-commit", default=DEFAULT_PATT_COMMIT)
    parser.add_argument("--snapshot-root", default=os.environ.get("SOURCE_SNAPSHOT_ROOT", "registry/upstream_snapshots"))
    parser.add_argument("--backup-root", default=".cache/focused-rebuild/backups")
    parser.add_argument(
        "--skip-patt",
        action="store_true",
        help=(
            "skip remote PATT refresh and rebuild the compact family/technology "
            "plane from the local payload index"
        ),
    )
    return parser.parse_args()


def _merge_rebuild_details(
    store: CompactDetailStore,
    original_records: tuple[dict[str, object], ...],
    staged_records: tuple[dict[str, object], ...],
) -> tuple[dict[str, object], ...]:
    """Retain details previously removed from the active graph."""
    return merge_compact_detail_records(
        store.query(), original_records, staged_records,
    )


def main() -> int:
    args = _parse_args()
    settings = Settings.from_env()
    repository = Neo4jGraphRepository(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    try:
        canonical_wstg_snapshots = store_canonical_wstg_snapshots(
            SnapshotStore(args.snapshot_root)
        )
        original_nodes = repository.nodes()
        original_edges = repository.edges()
        backup = _backup_graph(Path(args.backup_root), original_nodes, original_edges, patt_commit=args.patt_commit)
        original_compact_records = collect_compact_detail_records(
            original_nodes,
            original_edges,
        )

        selected_nodes, selected_edges, report = build_focused_projection(
            original_nodes,
            original_edges,
            target_cwes=FOCUSED_CWE_IDS,
        )
        staging = InMemoryGraphRepository()
        staging.replace_all(nodes=selected_nodes, edges=selected_edges)
        patt_index = PATTIndex(Path(args.snapshot_root) / "patt_payloads.sqlite3")
        patt_report: dict[str, object]
        if not args.skip_patt:
            patt_report = _add_patt(
                staging,
                snapshot_root=args.snapshot_root,
                commit=args.patt_commit,
                retrieved_at=current_utc(),
            )
            _deduplicate_technologies(staging)
        else:
            patt_report = {"remote_refresh": "skipped"}
        semantic_plane_report = restore_patt_semantic_plane(
            staging,
            payload_index=patt_index,
            cwe_ids=PATT_NATIVE_CWE_IDS,
        )
        if (
            semantic_plane_report.cwe_count != len(PATT_NATIVE_CWE_IDS)
            or semantic_plane_report.family_count == 0
        ):
            raise ValueError(
                "PATT payload index is incomplete for the focused graph: "
                f"covered {semantic_plane_report.cwe_count}/{len(PATT_NATIVE_CWE_IDS)} "
                f"native CWEs with {semantic_plane_report.family_count} families"
            )
        patt_report["remote_refresh"] = "skipped" if args.skip_patt else "completed"
        patt_report["semantic_plane"] = asdict(semantic_plane_report)
        staged_compact_records = collect_compact_detail_records(
            staging.nodes(),
            staging.edges(),
        )
        compact_detail_store = CompactDetailStore(
            Path(args.snapshot_root) / COMPACT_DETAILS_DB_NAME
        )
        compact_detail_records = _merge_rebuild_details(
            compact_detail_store, original_compact_records, staged_compact_records,
        )
        compact_detail_report = compact_detail_store.replace_all(compact_detail_records)

        # PATT import intentionally retains document/evidence provenance in
        # the staging graph so it can be exported losslessly.  The active
        # graph keeps the family/technology semantic plane only.
        compact_ids = {
            node.node_id
            for node in staging.nodes()
            if is_compact_detail_node(node)
        }
        if compact_ids:
            staging.replace_all(
                nodes=[node for node in staging.nodes() if node.node_id not in compact_ids],
                edges=[
                    edge
                    for edge in staging.edges()
                    if edge.subject_id not in compact_ids and edge.object_id not in compact_ids
                ],
            )
        compacted_nodes, compacted_edges, version_range_report = compact_version_ranges(
            staging.nodes(),
            staging.edges(),
        )
        staging.replace_all(nodes=compacted_nodes, edges=compacted_edges)
        profiles = rebuild_cwe_profiles(staging)
        cooccurrence = mine_cooccurrence(staging)
        final_nodes = staging.nodes()
        final_edges = staging.edges()
        validate_focused_projection(final_nodes, final_edges, target_cwes=FOCUSED_CWE_IDS)
        snapshot_count = _validate_snapshot_objects(
            args.snapshot_root,
            final_nodes,
            final_edges,
            extra_digests=compact_detail_store.snapshot_digests(),
        )

        repository.replace_database(nodes=final_nodes, edges=final_edges)
        final_report = FocusedProjectionReport(
            target_cwes=report.target_cwes,
            cwe_count=sum(node.label == "CWE" for node in final_nodes),
            cve_count=sum(node.label in {"CVE", "GHSA"} for node in final_nodes),
            excluded_cves=report.excluded_cves,
            capec_count=sum(node.label == "CAPEC" for node in final_nodes),
            wstg_case_count=sum(node.label == "WSTGCase" for node in final_nodes),
            strategy_count=sum(node.label == "TestStrategy" for node in final_nodes),
            patt_family_count=sum(node.label == "PayloadFamily" for node in final_nodes),
            technology_count=sum(node.label == "Technology" for node in final_nodes),
            patt_document_node_count=sum(node.label == "PATTDocument" for node in final_nodes),
            patt_payload_node_count=sum(node.label == "Payload" for node in final_nodes),
            node_count=len(final_nodes),
            edge_count=len(final_edges),
        )
        print(json.dumps({
            "backup": str(backup),
            "projection": asdict(final_report),
            "profiles": asdict(profiles),
            "cooccurrence": asdict(cooccurrence),
            "patt": patt_report,
            "canonical_wstg_snapshot_count": len(canonical_wstg_snapshots),
            "verified_snapshot_reference_count": snapshot_count,
            "compact_details": asdict(compact_detail_report),
            "version_ranges": asdict(version_range_report),
            "excluded_cves": list(report.excluded_cves),
        }, indent=2, ensure_ascii=False, sort_keys=True, default=str))
        return 0
    finally:
        repository.close()


if __name__ == "__main__":
    raise SystemExit(main())
