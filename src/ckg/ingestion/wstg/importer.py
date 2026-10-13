"""Project WSTG cases into test strategies without importing payload bodies."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import yaml

from ckg.domain.entities.test_knowledge import InputSurface, Oracle, TestStrategy, WSTGCase
from ckg.domain.entities.technique import Technique
from ckg.domain.entities.evidence import Evidence
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.ingestion.wstg.section_parser import parse_sections
from ckg.ingestion.wstg.semantic_normalizer import normalize_section
from ckg.ingestion.digests import verify_snapshot_digest


def _stable_id(prefix: str, *parts: str) -> str:
    return f"{prefix}-{hashlib.sha256(chr(31).join(parts).encode()).hexdigest()[:24]}"


@dataclass(frozen=True)
class WSTGImportReport:
    wstg_id: str
    strategy_count: int
    technique_count: int
    channel_count: int
    oracle_count: int
    input_surface_count: int
    target_cwe_count: int
    unresolved_cwe_ids: tuple[str, ...]


def import_wstg_case(
    repository: GraphRepository,
    *,
    wstg_id: str,
    title: str,
    markdown: str,
    source_release: str,
    source_snapshot_digest: str,
    source_url: str,
    retrieved_at: datetime,
    mapping_path: str | Path,
    target_cwe_ids: tuple[str, ...] = (),
) -> WSTGImportReport:
    verify_snapshot_digest(markdown.encode("utf-8"), source_snapshot_digest)
    """Import a single WSTG document with optional explicit CWE source mapping."""
    mapping = yaml.safe_load(Path(mapping_path).read_text(encoding="utf-8"))
    cwe_ids = {node.node_id for node in repository.nodes("CWE")}
    case = WSTGCase(wstg_id=wstg_id, title=title, source_release=source_release, source_snapshot_digest=source_snapshot_digest)
    strategy = TestStrategy(strategy_id=f"TSTRAT-{wstg_id}", name=title, source_kind="wstg")
    evidence_id = _stable_id("EVID-WSTG", wstg_id, source_snapshot_digest)
    evidence = Evidence(evidence_id=evidence_id, kind="wstg_markdown", content_digest=source_snapshot_digest, retrieved_at=retrieved_at, source_url=source_url)
    nodes = [
        GraphNode(label="WSTGCase", node_id=wstg_id, props={**case.model_dump(mode="json"), "source_url": source_url, "retrieved_at": retrieved_at.isoformat()}),
        GraphNode(label="TestStrategy", node_id=strategy.strategy_id, props=strategy.model_dump(mode="json")),
        GraphNode(label="Evidence", node_id=evidence_id, props=evidence.model_dump(mode="json", exclude_none=True)),
    ]
    edges = [
        GraphEdge(edge_id=_stable_id("EDGE-DESCRIBES", wstg_id, strategy.strategy_id), edge_type="DESCRIBES", subject_id=wstg_id, object_id=strategy.strategy_id, props={"source_snapshot_digest": source_snapshot_digest, "locator": "/", "evidence_id": evidence_id}),
        GraphEdge(edge_id=_stable_id("EDGE-WSTG-SUPPORTED-BY", wstg_id, evidence_id), edge_type="SUPPORTED_BY", subject_id=wstg_id, object_id=evidence_id),
    ]
    known_node_ids = {node.node_id for node in repository.nodes()} | {node.node_id for node in nodes}
    techniques: set[str] = set()
    channels: set[str] = set()
    oracles: set[str] = set()
    input_surfaces: set[str] = set()
    for section in parse_sections(markdown):
        mentioned_techniques, mentioned_channels, mentioned_oracles, mentioned_inputs = normalize_section(section, mapping_path=mapping_path)
        for mention in mentioned_techniques:
            technique_id = mention.technique_id
            techniques.add(technique_id)
            item = mapping["techniques"][technique_id]
            if technique_id not in known_node_ids:
                technique = Technique(technique_id=technique_id, name=item["name"], aliases=tuple(item.get("aliases", [])))
                nodes.append(GraphNode(label="Technique", node_id=technique_id, props=technique.model_dump(mode="json")))
                known_node_ids.add(technique_id)
            edges.append(GraphEdge(edge_id=_stable_id("EDGE-USES-TECHNIQUE", strategy.strategy_id, technique_id, mention.locator), edge_type="USES_TECHNIQUE", subject_id=strategy.strategy_id, object_id=technique_id, props={"source_snapshot_digest": source_snapshot_digest, "locator": mention.locator, "source_url": source_url, "evidence_id": evidence_id}))
        for mention in mentioned_channels:
            channel_id = mention.channel_id
            channels.add(channel_id)
            item = mapping["channels"][channel_id]
            if channel_id not in known_node_ids:
                nodes.append(GraphNode(label="CallbackChannel", node_id=channel_id, props={"channel_id": channel_id, "name": item["name"], "aliases": item.get("aliases", [])}))
                known_node_ids.add(channel_id)
            edges.append(GraphEdge(edge_id=_stable_id("EDGE-USES-CHANNEL", strategy.strategy_id, channel_id, mention.locator), edge_type="USES_CHANNEL", subject_id=strategy.strategy_id, object_id=channel_id, props={"source_snapshot_digest": source_snapshot_digest, "locator": mention.locator, "source_url": source_url, "evidence_id": evidence_id}))
        for mention in mentioned_oracles:
            oracle_id = mention.oracle_id
            oracles.add(oracle_id)
            item = mapping["oracles"][oracle_id]
            if oracle_id not in known_node_ids:
                oracle = Oracle(oracle_id=oracle_id, name=item["name"])
                nodes.append(GraphNode(label="Oracle", node_id=oracle_id, props=oracle.model_dump(mode="json")))
                known_node_ids.add(oracle_id)
            edges.append(GraphEdge(edge_id=_stable_id("EDGE-USES-ORACLE", strategy.strategy_id, oracle_id, mention.locator), edge_type="USES_ORACLE", subject_id=strategy.strategy_id, object_id=oracle_id, props={"source_snapshot_digest": source_snapshot_digest, "locator": mention.locator, "evidence_id": evidence_id}))
        for mention in mentioned_inputs:
            input_id = mention.input_surface_id
            input_surfaces.add(input_id)
            item = mapping["input_surfaces"][input_id]
            if input_id not in known_node_ids:
                input_surface = InputSurface(input_surface_id=input_id, name=item["name"])
                nodes.append(GraphNode(label="InputSurface", node_id=input_id, props=input_surface.model_dump(mode="json")))
                known_node_ids.add(input_id)
            edges.append(GraphEdge(edge_id=_stable_id("EDGE-APPLIES-TO", strategy.strategy_id, input_id, mention.locator), edge_type="APPLIES_TO", subject_id=strategy.strategy_id, object_id=input_id, props={"source_snapshot_digest": source_snapshot_digest, "locator": mention.locator, "evidence_id": evidence_id}))
    unresolved: set[str] = set()
    for cwe_id in sorted(set(target_cwe_ids)):
        if cwe_id not in cwe_ids:
            unresolved.add(cwe_id)
            continue
        edges.append(GraphEdge(edge_id=_stable_id("EDGE-TARGETS-WEAKNESS", strategy.strategy_id, cwe_id), edge_type="TARGETS_WEAKNESS", subject_id=strategy.strategy_id, object_id=cwe_id, props={"source": "explicit-wstg-mapping", "source_snapshot_digest": source_snapshot_digest}))
    repository.atomic_write(nodes=nodes, edges=edges)
    return WSTGImportReport(wstg_id, 1, len(techniques), len(channels), len(oracles), len(input_surfaces), len(target_cwe_ids) - len(unresolved), tuple(sorted(unresolved)))
