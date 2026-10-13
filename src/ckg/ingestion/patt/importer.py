"""Project PATT methodology/bypass metadata while retaining raw bytes as evidence only."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import yaml

from ckg.domain.entities.evidence import Evidence
from ckg.domain.entities.technique import Technique
from ckg.domain.entities.test_knowledge import ProbeFamily
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.ingestion.patt.markdown_parser import parse_patt_sections
from ckg.ingestion.patt.technique_extractor import extract_techniques
from ckg.ingestion.digests import verify_snapshot_digest


def _stable_id(prefix: str, *parts: str) -> str:
    return f"{prefix}-{hashlib.sha256(chr(31).join(parts).encode()).hexdigest()[:24]}"


@dataclass(frozen=True)
class PATTImportReport:
    document_id: str
    section_count: int
    technique_count: int
    bypass_count: int


def import_patt_document(
    repository: GraphRepository,
    *,
    document_id: str,
    title: str,
    markdown: str,
    source_commit: str,
    source_snapshot_digest: str,
    source_url: str,
    retrieved_at: datetime,
    mapping_path: str | Path,
) -> PATTImportReport:
    verify_snapshot_digest(markdown.encode("utf-8"), source_snapshot_digest)
    mapping = yaml.safe_load(Path(mapping_path).read_text(encoding="utf-8"))
    sections = parse_patt_sections(markdown)
    evidence_id = _stable_id("EVID-PATT", document_id, source_snapshot_digest)
    evidence = Evidence(evidence_id=evidence_id, kind="patt_markdown", content_digest=source_snapshot_digest, retrieved_at=retrieved_at, source_url=source_url)
    nodes = [
        GraphNode(label="PATTDocument", node_id=document_id, props={"document_id": document_id, "title": title, "source_commit": source_commit, "source_snapshot_digest": source_snapshot_digest, "source_url": source_url, "retrieved_at": retrieved_at.isoformat()}),
        GraphNode(label="Evidence", node_id=evidence_id, props=evidence.model_dump(mode="json", exclude_none=True)),
    ]
    edges: list[GraphEdge] = [GraphEdge(edge_id=_stable_id("EDGE-PATT-SUPPORTED-BY", document_id, evidence_id), edge_type="SUPPORTED_BY", subject_id=document_id, object_id=evidence_id)]
    existing = {node.node_id for node in repository.nodes()} | {document_id}
    techniques: set[str] = set()
    bypasses: set[str] = set()
    for section in sections:
        section_id = _stable_id("PATT-SECTION", document_id, str(section.index))
        nodes.append(GraphNode(label="PATTSection", node_id=section_id, props={"heading": section.heading, "path": list(section.path), "source_snapshot_digest": source_snapshot_digest, "locator": f"/sections/{section.index}"}))
        edges.append(GraphEdge(edge_id=_stable_id("EDGE-HAS-SECTION", document_id, section_id), edge_type="HAS_SECTION", subject_id=document_id, object_id=section_id))
        mentioned_techniques, mentioned_channels = extract_techniques(section, mapping_path=mapping_path)
        probe_family_id = None
        if mentioned_techniques:
            probe_family_id = _stable_id("PROBE-FAMILY", document_id, str(section.index))
            probe_family = ProbeFamily(probe_family_id=probe_family_id, name=section.heading)
            nodes.append(GraphNode(label="ProbeFamily", node_id=probe_family_id, props=probe_family.model_dump(mode="json")))
            edges.append(GraphEdge(edge_id=_stable_id("EDGE-SECTION-HAS-PROBE-FAMILY", section_id, probe_family_id), edge_type="HAS_PROBE_FAMILY", subject_id=section_id, object_id=probe_family_id, props={"source_snapshot_digest": source_snapshot_digest, "locator": f"/sections/{section.index}"}))
        for mention in mentioned_techniques:
            technique_id = mention.technique_id
            techniques.add(technique_id)
            if technique_id not in existing:
                item = mapping["techniques"][technique_id]
                technique = Technique(technique_id=technique_id, name=item["name"], aliases=tuple(item.get("aliases", [])))
                nodes.append(GraphNode(label="Technique", node_id=technique_id, props=technique.model_dump(mode="json")))
                existing.add(technique_id)
            edges.append(GraphEdge(edge_id=_stable_id("EDGE-SECTION-DESCRIBES", section_id, technique_id), edge_type="DESCRIBES_TECHNIQUE", subject_id=section_id, object_id=technique_id, props={"source_snapshot_digest": source_snapshot_digest, "locator": mention.locator, "evidence_id": evidence_id}))
            edges.append(GraphEdge(edge_id=_stable_id("EDGE-PROBE-FAMILY-USES", probe_family_id or section_id, technique_id), edge_type="USES_TECHNIQUE", subject_id=probe_family_id or section_id, object_id=technique_id, props={"source_snapshot_digest": source_snapshot_digest, "locator": mention.locator, "evidence_id": evidence_id}))
        for mention in mentioned_channels:
            channel_id = mention.channel_id
            if channel_id not in existing:
                item = mapping["channels"][channel_id]
                nodes.append(GraphNode(label="CallbackChannel", node_id=channel_id, props={"channel_id": channel_id, "name": item["name"], "aliases": item.get("aliases", [])}))
                existing.add(channel_id)
            edges.append(GraphEdge(edge_id=_stable_id("EDGE-SECTION-USES-CHANNEL", section_id, channel_id, mention.locator), edge_type="USES_CHANNEL", subject_id=probe_family_id or section_id, object_id=channel_id, props={"source_snapshot_digest": source_snapshot_digest, "locator": mention.locator, "evidence_id": evidence_id}))
        if "bypass" in section.heading.lower():
            bypass_id = _stable_id("BYPASS", document_id, str(section.index))
            bypasses.add(bypass_id)
            nodes.append(GraphNode(label="BypassTechnique", node_id=bypass_id, props={"name": section.heading, "source_snapshot_digest": source_snapshot_digest, "locator": f"/sections/{section.index}"}))
            edges.append(GraphEdge(edge_id=_stable_id("EDGE-HAS-BYPASS", section_id, bypass_id), edge_type="DESCRIBES_BYPASS", subject_id=section_id, object_id=bypass_id, props={"source_snapshot_digest": source_snapshot_digest, "locator": f"/sections/{section.index}"}))
    repository.atomic_write(nodes=nodes, edges=edges)
    return PATTImportReport(document_id, len(sections), len(techniques), len(bypasses))
