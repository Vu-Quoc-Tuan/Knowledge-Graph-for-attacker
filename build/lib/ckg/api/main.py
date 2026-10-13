"""Dependency-light v2 Module-1 HTTP API, isolated from legacy UI routes."""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ckg.application.ingest_cve import ingest_structured_source, preview_structured_record_ids
from ckg.application.analyze_vulnerability import analyze_cve
from ckg.application.ingest_cwe import ingest_cwe_catalog
from ckg.ingestion.cve.cve_services_client import CVE_SERVICES_RECORD_URL, fetch_record
from ckg.ingestion.cve.nvd_client import NVD_CVE_API_URL, build_search_url, fetch_cve, search_cves
from ckg.ingestion.cwe.parser import parse_cwe_catalog
from ckg.ingestion.patt.payload_index import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    PATTIndex,
)
from ckg.constraints.evaluator import EnvironmentSnapshot
from ckg.domain.entities.observation import ExecutionObservation, ObservationResult
from ckg.feedback.evidence_quality import ObservationQuality
from ckg.feedback.updater import process_observation
from ckg.graph.models import GraphNode
from ckg.graph.ports import GraphRepository
from ckg.provenance.compact_details import COMPACT_DETAILS_DB_NAME, CompactDetailStore
from ckg.linking.historical.hybrid_retriever import retrieve_historical_neighbors
from ckg.reasoning.subgraph.builder import build_local_subgraph
from ckg.reasoning.subgraph.budgets import SubgraphBudget
from ckg.scenario.discoverer import discover_scenarios


LOGGER = logging.getLogger(__name__)
DEFAULT_MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024
MAX_SEARCH_CANDIDATES = 1000


class _RequestBodyTooLarge(Exception):
    """Internal control-flow marker after the 413 response has been written."""


def _time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def _node_dict(node):
    return {"id": node.node_id, "label": node.label, "props": node.props}


def _query_int(query: dict[str, list[str]], name: str) -> int | None:
    raw = query.get(name, [None])[0]
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error


class CKGApplication:
    def __init__(self, repository: GraphRepository, *, snapshot_root: str) -> None:
        self.repository = repository
        self.snapshot_root = snapshot_root
        if repository.backend_name == "neo4j":
            repository.set_compact_detail_store(
                CompactDetailStore(Path(snapshot_root) / COMPACT_DETAILS_DB_NAME)
            )
        self.patt_index = PATTIndex(Path(snapshot_root) / "patt_payloads.sqlite3")
        self.ui_root = Path(__file__).resolve().parent.parent / "ui" / "v2"
        if not self.ui_root.is_dir():
            raise FileNotFoundError(f"canonical v2 UI assets are missing: {self.ui_root}")

    def backend_info(self) -> dict[str, str]:
        return {"graphSchema": "ckg-v2", "backend": self.repository.backend_name}

    def cve(self, identifier: str) -> dict:
        node = next((item for item in self.repository.nodes() if item.node_id == identifier), None)
        if node is None or node.label not in {"CVE", "GHSA"}:
            raise KeyError(identifier)
        assertions = [edge.object_id for edge in self.repository.edges("HAS_WEAKNESS_ASSERTION") if edge.subject_id == identifier]
        assertion_nodes = {item.node_id: item for item in self.repository.nodes("WeaknessAssertion")}
        return {"vulnerability": _node_dict(node), "weaknesses": [_node_dict(assertion_nodes[item]) for item in assertions if item in assertion_nodes]}

    def subgraph(self, identifier: str, *, as_of: datetime | None = None) -> dict:
        result = build_local_subgraph(self.repository, identifier, budget=SubgraphBudget(), as_of=as_of)
        return {"root_id": result.root_id, "nodes": [_node_dict(node) for node in result.nodes], "edges": [edge.model_dump(mode="json") for edge in result.edges], "truncated": result.truncated, "dropped_node_ids": result.dropped_node_ids, "temporal_excluded_node_ids": result.temporal_excluded_node_ids, "as_of": as_of.isoformat() if as_of else None}

    def weaknesses(self, identifier: str) -> dict:
        return self.cve(identifier)

    def historical_neighbors(self, identifier: str, *, as_of: datetime | None = None) -> dict:
        return {"vulnerability_id": identifier, "neighbors": [item.__dict__ | {"sources": sorted(item.sources)} for item in retrieve_historical_neighbors(self.repository, identifier, as_of=as_of)]}

    def scenarios(self, identifier: str, *, environment: EnvironmentSnapshot | None = None, as_of: datetime | None = None) -> dict:
        candidates = discover_scenarios(self.repository, identifier, environment=environment, as_of=as_of)
        return {"vulnerability_id": identifier, "scenarios": [candidate.model_dump(mode="json") for candidate in candidates]}

    def cwe_profile(self, identifier: str) -> dict:
        profile_id = f"CWE-PROFILE-{identifier}"
        node = next((item for item in self.repository.nodes("CWEContextProfile") if item.node_id == profile_id), None)
        if node is None:
            raise KeyError(identifier)
        associations = [edge.object_id for edge in self.repository.edges("HAS_ASSOCIATION") if edge.subject_id == profile_id]
        association_nodes = {item.node_id: item for item in self.repository.nodes("ProfileAssociation")}
        return {"profile": _node_dict(node), "associations": [_node_dict(association_nodes[item]) for item in associations if item in association_nodes and association_nodes[item].props.get("stale") is not True]}

    def cwe_scenarios(self, identifier: str) -> dict:
        scenarios = [node for node in self.repository.nodes("Scenario") if identifier in (node.props.get("weakness_ids") or [])]
        return {"cwe_id": identifier, "scenarios": [_node_dict(node) for node in scenarios]}

    @staticmethod
    def _payload_page(*, limit: int, offset: int) -> tuple[int, int]:
        limit = int(limit)
        offset = int(offset)
        if limit < 1 or limit > MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
        if offset < 0:
            raise ValueError("offset must be non-negative")
        return limit, offset

    @staticmethod
    def _payload_item(node: GraphNode) -> dict:
        return {
            "id": node.node_id,
            "payload_id": node.node_id,
            "value": node.props.get("value"),
            "payload_digest": node.props.get("payload_digest"),
            "family_key": node.props.get("family_key"),
            "family_name": node.props.get("family_name"),
            "technology": node.props.get("technology"),
            "source_file": node.props.get("source_file"),
            "source_url": node.props.get("source_url"),
            "source_revision": node.props.get("source_revision"),
            "source_kind": node.props.get("source_kind"),
            "source_snapshot_digest": node.props.get("source_snapshot_digest"),
            "section_heading": node.props.get("section_heading"),
            "locator": node.props.get("locator"),
            "extraction": node.props.get("extraction"),
            "origin": node.props.get("origin"),
            "curation_status": node.props.get("curation_status"),
            "validation_status": node.props.get("validation_status"),
        }

    def _legacy_payload_items(self, identifier: str) -> list[dict]:
        family_ids = {
            edge.object_id
            for edge in self.repository.edges("HAS_PAYLOAD_FAMILY")
            if edge.subject_id == identifier
        }
        payload_ids = {
            edge.subject_id
            for edge in self.repository.edges("IN_FAMILY")
            if edge.object_id in family_ids
        }
        items = [
            self._payload_item(node) | {"cwe_id": identifier}
            for node in self.repository.nodes("Payload")
            if node.node_id in payload_ids
        ]
        return sorted(
            items,
            key=lambda item: (
                str(item["family_key"] or ""),
                str(item["technology"] or ""),
                str(item["value"] or ""),
            ),
        )

    def _legacy_family_summaries(self, items: list[dict]) -> list[dict]:
        grouped: dict[tuple[str, str], dict] = {}
        for item in items:
            key = (str(item.get("family_key") or ""), str(item.get("family_name") or ""))
            summary = grouped.setdefault(
                key,
                {"family_key": key[0], "family_name": key[1], "payload_count": 0, "technologies": set()},
            )
            summary["payload_count"] += 1
            if item.get("technology"):
                summary["technologies"].add(item["technology"])
        return [
            {**summary, "technologies": sorted(summary["technologies"])}
            for _, summary in sorted(grouped.items())
        ]

    def cwe_payloads(
        self,
        identifier: str,
        *,
        family: str | None = None,
        technology: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> dict:
        """Return compact, paginated PATT references without execution claims."""
        if not any(node.node_id == identifier and node.label == "CWE" for node in self.repository.nodes("CWE")):
            raise KeyError(identifier)
        limit, offset = self._payload_page(limit=limit, offset=offset)
        indexed = self.patt_index.query(
            cwe_ids=(identifier,), family=family, technology=technology,
            limit=limit, offset=offset,
        )
        has_index_rows = self.patt_index.query(cwe_ids=(identifier,), limit=1)["total"] > 0
        if has_index_rows:
            page = indexed
            storage = "sidecar_index"
        else:
            all_items = self._legacy_payload_items(identifier)
            if family:
                all_items = [item for item in all_items if item.get("family_key") == family]
            if technology:
                all_items = [item for item in all_items if item.get("technology") == technology]
            page_items = all_items[offset : offset + limit]
            page = {
                "payloads": page_items,
                "families": self._legacy_family_summaries(all_items),
                "total": len(all_items),
                "limit": limit,
                "offset": offset,
                "truncated": offset + len(page_items) < len(all_items),
            }
            storage = "legacy_graph"
        return {
            "cwe_id": identifier,
            "reference_only": True,
            "payloads": page["payloads"],
            "families": page["families"],
            "total": page["total"],
            "limit": page["limit"],
            "offset": page["offset"],
            "truncated": page["truncated"],
            "payload_storage": storage,
        }

    def cve_payloads(
        self,
        identifier: str,
        *,
        family: str | None = None,
        technology: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> dict:
        self.cve(identifier)
        limit, offset = self._payload_page(limit=limit, offset=offset)
        assertion_ids = {
            edge.object_id
            for edge in self.repository.edges("HAS_WEAKNESS_ASSERTION")
            if edge.subject_id == identifier
        }
        cwe_ids = sorted({
            edge.object_id
            for edge in self.repository.edges("MAPS_TO")
            if edge.subject_id in assertion_ids
        })
        if not cwe_ids:
            page = {
                "payloads": [], "families": [], "total": 0,
                "limit": limit, "offset": offset, "truncated": False,
            }
            storage = "sidecar_index"
        else:
            indexed = self.patt_index.query(
                cwe_ids=tuple(cwe_ids), family=family, technology=technology,
                limit=limit, offset=offset,
            )
            has_index_rows = self.patt_index.query(cwe_ids=tuple(cwe_ids), limit=1)["total"] > 0
            if has_index_rows:
                page = indexed
                storage = "sidecar_index"
            else:
                all_items = [
                    {"cwe_id": cwe_id, **item}
                    for cwe_id in cwe_ids
                    for item in self._legacy_payload_items(cwe_id)
                ]
                if family:
                    all_items = [item for item in all_items if item.get("family_key") == family]
                if technology:
                    all_items = [item for item in all_items if item.get("technology") == technology]
                all_items.sort(key=lambda item: (
                    str(item.get("cwe_id") or ""),
                    str(item.get("family_key") or ""),
                    str(item.get("technology") or ""),
                    str(item.get("value") or ""),
                ))
                page_items = all_items[offset : offset + limit]
                page = {
                    "payloads": page_items,
                    "families": self._legacy_family_summaries(all_items),
                    "total": len(all_items),
                    "limit": limit,
                    "offset": offset,
                    "truncated": offset + len(page_items) < len(all_items),
                }
                storage = "legacy_graph"
        return {
            "vulnerability_id": identifier,
            "weakness_ids": cwe_ids,
            "reference_only": True,
            "payloads": page["payloads"],
            "families": page["families"],
            "total": page["total"],
            "limit": page["limit"],
            "offset": page["offset"],
            "truncated": page["truncated"],
            "payload_storage": storage,
        }

    @staticmethod
    def _year_bounds(
        *,
        from_year: int | None,
        to_year: int | None,
        recent_years: int = 5,
    ) -> tuple[int, int]:
        current_year = datetime.now(timezone.utc).year
        if from_year is not None:
            from_year = int(from_year)
        if to_year is not None:
            to_year = int(to_year)
        recent_years = int(recent_years)
        if recent_years < 1 or recent_years > 20:
            raise ValueError("recent_years must be between 1 and 20")
        if from_year is None and to_year is None:
            return current_year - recent_years + 1, current_year
        if to_year is None:
            to_year = current_year
        if from_year is None:
            from_year = to_year - recent_years + 1
        if from_year < 1999 or to_year < 1999 or from_year > 2100 or to_year > 2100:
            raise ValueError("year must be between 1999 and 2100")
        if from_year > to_year:
            raise ValueError("from_year must be less than or equal to to_year")
        return from_year, to_year

    @staticmethod
    def _search_item(match) -> dict:
        vulnerability = match.vulnerability
        published_at = vulnerability.props.get("published_at")
        try:
            published_year = int(str(published_at)[:4]) if published_at else None
        except (TypeError, ValueError):
            published_year = None
        products = [
            {
                "vendor": product.props.get("vendor"),
                "name": product.props.get("name"),
                "package_name": product.props.get("package_name"),
                "ecosystem": product.props.get("ecosystem"),
                "cpe_uri": product.props.get("cpe_uri"),
                "aliases": product.props.get("aliases", []),
                "source_pointer": product.props.get("source_pointer"),
            }
            for product in match.products
        ]
        versions = [
            {
                "expression": version.props.get("expression"),
                "status": version.props.get("status"),
                "ecosystem": version.props.get("ecosystem"),
                "source_pointer": version.props.get("source_pointer"),
            }
            for version in match.versions
        ]
        sources = [
            {
                "record_id": source.props.get("record_id"),
                "source_kind": source.props.get("source_kind"),
                "source_url": source.props.get("source_url"),
                "source_revision": source.props.get("source_revision"),
                "state": source.props.get("state"),
                "snapshot_digest": source.props.get("snapshot_digest"),
            }
            for source in match.sources
        ]
        return {
            "id": vulnerability.node_id,
            "label": vulnerability.label,
            "title": vulnerability.props.get("title", vulnerability.node_id),
            "description": vulnerability.props.get("description", ""),
            "published_at": published_at,
            "published_year": published_year,
            "aliases": vulnerability.props.get("aliases", []),
            "affected_products": products,
            "affected_versions": versions,
            "sources": sources,
            "relevance": match.relevance,
            "match_reason": match.match_reason,
        }

    @staticmethod
    def _validate_search_paging(*, limit: int, offset: int) -> None:
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        if offset < 0:
            raise ValueError("offset must not be negative")
        if offset + limit > MAX_SEARCH_CANDIDATES:
            raise ValueError(f"offset plus limit must not exceed {MAX_SEARCH_CANDIDATES}")

    def list_cves_page(
        self,
        *,
        technology: str | None = None,
        from_year: int | None = None,
        to_year: int | None = None,
        limit: int = 100,
        offset: int = 0,
        recent_years: int = 5,
    ) -> dict:
        self._validate_search_paging(limit=limit, offset=offset)
        technology = " ".join(technology.split()) if technology else None
        if technology:
            start, end = self._year_bounds(
                from_year=from_year, to_year=to_year, recent_years=recent_years
            )
            matches = self.repository.search_vulnerabilities(
                technology.strip(),
                from_year=start,
                to_year=end,
                limit=max(100, offset + limit),
            )
            items = [
                self._search_item(match)
                for match in matches
            ]
            truncated = len(items) >= max(100, offset + limit)
            total = None if truncated else len(items)
            return {
                "cves": items[offset : offset + limit],
                "total": total,
                "returned": len(items[offset : offset + limit]),
                "offset": offset,
                "limit": limit,
                "truncated": truncated,
            }
        cve_nodes = [node for node in self.repository.nodes() if node.label in {"CVE", "GHSA"}]
        if from_year is not None or to_year is not None:
            start, end = self._year_bounds(
                from_year=from_year, to_year=to_year, recent_years=recent_years
            )
            cve_nodes = [
                node for node in cve_nodes
                if isinstance(node.props.get("published_at"), str)
                and node.props["published_at"][:4].isdigit()
                and start <= int(node.props["published_at"][:4]) <= end
            ]
        items = [{"id": node.node_id, "label": node.label, "title": node.props.get("title", ""), "description": node.props.get("description", "")} for node in sorted(cve_nodes, key=lambda x: x.node_id)]
        page = items[offset : offset + limit]
        return {
            "cves": page,
            "total": len(items),
            "returned": len(page),
            "offset": offset,
            "limit": limit,
            "truncated": False,
        }

    def list_cves(
        self,
        *,
        technology: str | None = None,
        from_year: int | None = None,
        to_year: int | None = None,
        limit: int = 100,
        recent_years: int = 5,
    ) -> list[dict]:
        return self.list_cves_page(
            technology=technology,
            from_year=from_year,
            to_year=to_year,
            limit=limit,
            recent_years=recent_years,
        )["cves"]

    def ingest_cve_search(self, payload: dict) -> dict:
        technology = str(payload.get("technology") or "").strip()
        if not technology:
            raise ValueError("technology is required")
        from_year = int(payload["from_year"]) if payload.get("from_year") is not None else None
        to_year = int(payload["to_year"]) if payload.get("to_year") is not None else None
        start, end = self._year_bounds(
            from_year=from_year,
            to_year=to_year,
            recent_years=int(payload.get("recent_years", 5)),
        )
        source_kind = payload.get("source_kind", "nvd")
        if source_kind != "nvd":
            raise ValueError("batch technology search currently supports source_kind=nvd only")
        fetched = search_cves(
            technology,
            from_year=start,
            to_year=end,
            api_key=payload.get("nvd_api_key"),
            timeout=float(payload.get("timeout", 30.0)),
            max_records=int(payload.get("max_records", 20_000)),
            return_metadata=True,
        )
        if isinstance(fetched, tuple):
            raw_bytes, fetch_metadata = fetched
        else:
            raw_bytes, fetch_metadata = fetched, {"truncated": False, "upstream_total_known": False}
        source_url = payload.get("source_url") or build_search_url(technology, from_year=start, to_year=end)
        result = ingest_structured_source(
            self.repository,
            source_kind="nvd",
            raw_payload=raw_bytes,
            source_url=source_url,
            retrieved_at=_time(payload.get("retrieved_at")) or datetime.now().astimezone(),
            snapshot_root=self.snapshot_root,
            use_model=bool(payload.get("use_model", False)),
        )
        job_id = f"JOB-INGEST-CVE-SEARCH-{result.snapshot_digest.removeprefix('sha256:')[:24]}"
        self.repository.atomic_write(
            nodes=[GraphNode(label="IngestionJob", node_id=job_id, props={"job_id": job_id, "kind": "cve-search", "technology": technology, "from_year": start, "to_year": end, "snapshot_digest": result.snapshot_digest, "truncated": fetch_metadata["truncated"], "status": "COMPLETED"})],
            edges=[],
        )
        return {"job_id": job_id, "snapshot_digest": result.snapshot_digest, "report": asdict(result.report), "query": {"technology": technology, "from_year": start, "to_year": end}, "truncated": fetch_metadata["truncated"], "upstream_total_known": fetch_metadata["upstream_total_known"]}

    def ingest_cve(self, identifier: str, payload: dict) -> dict:
        source_kind = payload.get("source_kind", "cve_services")
        raw = payload.get("raw_payload")
        if not raw and ("title" in payload or "description" in payload or "cweId" in payload or "cwe_id" in payload):
            raw = payload
        if not raw:
            if source_kind == "cve_services":
                raw_bytes = fetch_record(identifier)
                source_url = payload.get("source_url") or CVE_SERVICES_RECORD_URL.format(cve_id=identifier)
            elif source_kind == "nvd":
                raw_bytes = fetch_cve(identifier, api_key=payload.get("nvd_api_key"))
                source_url = payload.get("source_url") or f"{NVD_CVE_API_URL}?cveId={identifier}"
            else:
                raise ValueError("raw_payload must be provided when source_kind is not cve_services or nvd")
        else:
            if isinstance(raw, dict):
                raw_dict = raw
            elif isinstance(raw, str):
                raw_dict = json.loads(raw)
            else:
                raw_dict = json.loads(raw.decode("utf-8"))
            if "cveMetadata" not in raw_dict and "vulnerabilities" not in raw_dict and "data" not in raw_dict:
                cve_id = raw_dict.get("cveId") or raw_dict.get("id") or identifier
                title = raw_dict.get("title") or f"Vulnerability {cve_id}"
                desc = raw_dict.get("description") or title
                cwe_id = raw_dict.get("cweId") or raw_dict.get("cwe_id")
                problem_types = []
                if cwe_id:
                    problem_types.append({"descriptions": [{"lang": "en", "cweId": cwe_id, "description": cwe_id}]})
                raw_dict = {
                    "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
                    "containers": {
                        "cna": {
                            "title": title,
                            "descriptions": [{"lang": "en", "value": desc}],
                            "problemTypes": problem_types,
                        }
                    }
                }
                source_kind = "cve_services"
            raw_bytes = json.dumps(raw_dict).encode("utf-8")
            source_url = payload.get("source_url") or f"custom://{identifier}"

        if identifier not in preview_structured_record_ids(source_kind=source_kind, raw_payload=raw_bytes):
            raise ValueError(f"payload did not describe requested vulnerability {identifier}")
        # Ingestion is deterministic by default. Merely configuring a model
        # credential must not turn a graph write into an unbounded external
        # inference call; callers opt in explicitly with use_model=true.
        use_model = bool(payload.get("use_model", False))
        result = ingest_structured_source(
            self.repository,
            source_kind=source_kind,
            raw_payload=raw_bytes,
            source_url=source_url,
            retrieved_at=_time(payload.get("retrieved_at")) or datetime.now().astimezone(),
            snapshot_root=self.snapshot_root,
            use_model=use_model,
        )
        job_id = f"JOB-INGEST-CVE-{identifier}-{result.snapshot_digest.removeprefix('sha256:')[:24]}"
        self.repository.atomic_write(nodes=[GraphNode(label="IngestionJob", node_id=job_id, props={"job_id": job_id, "kind": "cve", "target_id": identifier, "snapshot_digest": result.snapshot_digest, "status": "COMPLETED"})], edges=[])
        return {
            "job_id": job_id,
            "snapshot_digest": result.snapshot_digest,
            "report": asdict(result.report),
            "analyses": [asdict(item) for item in result.analyses],
        }

    def ingest_cwe(self, identifier: str, payload: dict) -> dict:
        raw = payload.get("raw_xml_base64")
        if not isinstance(raw, str):
            raise ValueError("raw_xml_base64 is required")
        raw_xml = base64.b64decode(raw)
        catalog = parse_cwe_catalog(raw_xml, source_snapshot_digest=payload["source_snapshot_digest"], retrieved_at=_time(payload["retrieved_at"]) or datetime.now().astimezone(), source_url=payload["source_url"])
        if identifier not in {weakness.cwe_id for weakness in catalog.weaknesses}:
            raise ValueError(f"catalog did not describe requested CWE {identifier}")
        result = ingest_cwe_catalog(self.repository, raw_xml=raw_xml, source_snapshot_digest=payload["source_snapshot_digest"], retrieved_at=_time(payload["retrieved_at"]) or datetime.now().astimezone(), source_url=payload["source_url"])
        job_id = f"JOB-INGEST-CWE-{identifier}-{payload['source_snapshot_digest'].removeprefix('sha256:')[:24]}"
        self.repository.atomic_write(nodes=[GraphNode(label="IngestionJob", node_id=job_id, props={"job_id": job_id, "kind": "cwe", "target_id": identifier, "snapshot_digest": payload["source_snapshot_digest"], "status": "COMPLETED"})], edges=[])
        return {"job_id": job_id, "import": result[0].__dict__, "enrichment": result[1].__dict__}

    def analyze_cve(self, identifier: str, payload: dict) -> dict:
        analysis = analyze_cve(
            self.repository,
            identifier,
            retrieved_at=_time(payload.get("retrieved_at")) or datetime.now().astimezone(),
            use_model=payload.get("use_model"),
        )
        return asdict(analysis)

    def feedback(self, payload: dict) -> dict:
        environment = payload["environment"]
        environment_id = environment["environment_id"]
        observation = ExecutionObservation(
            observation_id=payload["observation_id"],
            scenario_id=payload["scenario_id"],
            scenario_revision=payload.get("scenario_revision", 1),
            environment_id=environment_id,
            result=ObservationResult(payload["result"]),
            observed_at=_time(payload["observed_at"]) or datetime.now().astimezone(),
            evidence_ids=tuple(payload["evidence_ids"]),
            evidence_digests=tuple(payload["evidence_digests"]),
        )
        quality = ObservationQuality(**payload["quality"])
        env_node = GraphNode(label="Environment", node_id=environment_id, props=environment)
        result = process_observation(
            self.repository,
            observation=observation,
            scope_key=payload["scope_key"],
            quality=quality,
            environment_node=env_node,
        )
        return {"posterior_id": result.posterior_id, "alpha": result.posterior.alpha, "beta": result.posterior.beta, "applied_weight": result.applied_weight, "deduplicated": result.deduplicated}


def make_handler(app: CKGApplication, *, max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES):
    if max_request_body_bytes < 1:
        raise ValueError("max_request_body_bytes must be at least 1")

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status: int, body: dict) -> None:
            encoded = json.dumps(body, default=str, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _json(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as error:
                raise ValueError("Content-Length must be an integer") from error
            if length < 0:
                raise ValueError("Content-Length must not be negative")
            if length > max_request_body_bytes:
                self._reply(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request body too large"})
                raise _RequestBodyTooLarge
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("JSON body must be an object")
            return body

        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            if path in ("/healthz", "/api/v2/health"):
                self._reply(
                    HTTPStatus.OK,
                    {
                        "status": "healthy",
                        "service": "Graph Knowledge v2 API",
                        **app.backend_info(),
                        "repository": type(app.repository).__name__,
                    },
                )
                return
            if not path:
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/ui/v2/")
                self.end_headers()
                return
            if path == "/ui/v2":
                path = "/ui/v2/index.html"
            if path.startswith("/ui/v2/"):
                relative = path.removeprefix("/ui/v2/")
                candidate = (app.ui_root / relative).resolve()
                try:
                    candidate.relative_to(app.ui_root.resolve())
                except ValueError:
                    self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                if not candidate.is_file():
                    self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                content_type = {
                    ".html": "text/html; charset=utf-8",
                    ".css": "text/css; charset=utf-8",
                    ".js": "application/javascript; charset=utf-8",
                    ".svg": "image/svg+xml",
                }.get(candidate.suffix, "application/octet-stream")
                content = candidate.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.end_headers()
                self.wfile.write(content)
                return
            parts = path.split("/")
            query = parse_qs(parsed.query)
            try:
                body = None
                if path.startswith("/cves/") and path.endswith("/subgraph"):
                    body = app.subgraph(parts[2], as_of=_time(query.get("as_of", [None])[0]))
                elif path.startswith("/cves/") and path.endswith("/weaknesses"):
                    body = app.weaknesses(parts[2])
                elif path.startswith("/cves/") and path.endswith("/historical-neighbors"):
                    body = app.historical_neighbors(parts[2], as_of=_time(query.get("as_of", [None])[0]))
                elif path.startswith("/cves/") and path.endswith("/scenarios"):
                    body = app.scenarios(parts[2], as_of=_time(query.get("as_of", [None])[0]))
                elif path.startswith("/cves/") and path.endswith("/payloads"):
                    body = app.cve_payloads(
                        parts[2],
                        family=query.get("family", [None])[0],
                        technology=query.get("technology", [None])[0],
                        limit=_query_int(query, "limit") or DEFAULT_PAGE_SIZE,
                        offset=_query_int(query, "offset") or 0,
                    )
                elif path.startswith("/cwes/") and path.endswith("/profile"):
                    body = app.cwe_profile(parts[2])
                elif path.startswith("/cwes/") and path.endswith("/scenarios"):
                    body = app.cwe_scenarios(parts[2])
                elif path.startswith("/cwes/") and path.endswith("/payloads"):
                    body = app.cwe_payloads(
                        parts[2],
                        family=query.get("family", [None])[0],
                        technology=query.get("technology", [None])[0],
                        limit=_query_int(query, "limit") or DEFAULT_PAGE_SIZE,
                        offset=_query_int(query, "offset") or 0,
                    )
                elif path in ("/cves", "/cves/"):
                    technology = query.get("technology", [None])[0]
                    from_year = _query_int(query, "from_year")
                    to_year = _query_int(query, "to_year")
                    recent_years = _query_int(query, "recent_years") or 5
                    limit = _query_int(query, "limit") or 100
                    offset = _query_int(query, "offset") or 0
                    if technology and technology.strip():
                        effective_from, effective_to = app._year_bounds(
                            from_year=from_year,
                            to_year=to_year,
                            recent_years=recent_years,
                        )
                    else:
                        effective_from, effective_to = from_year, to_year
                    page = app.list_cves_page(
                        technology=technology,
                        from_year=from_year,
                        to_year=to_year,
                        limit=limit,
                        offset=offset,
                        recent_years=recent_years,
                    )
                    body = {
                        **page,
                        "query": {
                            "technology": technology,
                            "from_year": effective_from,
                            "to_year": effective_to,
                        },
                    }
                elif len(parts) == 3 and parts[1] == "cves":
                    body = app.cve(parts[2])
                if body is None:
                    self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
                else:
                    self._reply(HTTPStatus.OK, body)
            except KeyError:
                self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._reply(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Unhandled v2 GET error")
                self._reply(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal server error"})

        def do_POST(self):  # noqa: N802
            path = urlparse(self.path).path.rstrip("/")
            parts = path.split("/")
            try:
                payload = self._json()
                if path.startswith("/ingest/cve/"):
                    body = app.ingest_cve(parts[3], payload)
                elif path in ("/ingest/cves/search", "/ingest/cves/search/"):
                    body = app.ingest_cve_search(payload)
                elif path in ("/ingest/cve", "/ingest/cve/"):
                    cve_id = payload.get("cveId") or payload.get("cve_id") or payload.get("id")
                    if not cve_id:
                        raise ValueError("cveId or id is required in JSON body")
                    body = app.ingest_cve(cve_id, payload)
                elif path.startswith("/analyze/cve/"):
                    body = app.analyze_cve(parts[3], payload)
                elif path.startswith("/ingest/cwe/"):
                    body = app.ingest_cwe(parts[3], payload)
                elif path == "/feedback/executions":
                    body = app.feedback(payload)
                else:
                    self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                self._reply(HTTPStatus.OK, body)
            except _RequestBodyTooLarge:
                return
            except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
                self._reply(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Unhandled v2 POST error")
                self._reply(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal server error"})

        def log_message(self, format, *args):  # noqa: A003
            return
    return Handler
