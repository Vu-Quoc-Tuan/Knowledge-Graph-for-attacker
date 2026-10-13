"""Curated Canonical OWASP WSTG testing strategies for core web & software weaknesses."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ckg.domain.entities.evidence import Evidence
from ckg.domain.entities.technique import Technique
from ckg.domain.entities.test_knowledge import InputSurface, Oracle, TestStrategy, WSTGCase
from ckg.graph.models import GraphEdge, GraphNode
from ckg.graph.ports import GraphRepository
from ckg.provenance.store import SnapshotStore


def _stable_id(prefix: str, *parts: str) -> str:
    return f"{prefix}-{hashlib.sha256(chr(31).join(parts).encode()).hexdigest()[:24]}"


@dataclass(frozen=True)
class CanonicalWSTGStrategyDef:
    wstg_id: str
    title: str
    target_cwes: tuple[str, ...]
    techniques: tuple[str, ...]
    channels: tuple[str, ...]
    oracles: tuple[str, ...]
    input_surfaces: tuple[str, ...]
    description: str


CANONICAL_WSTG_STRATEGIES: tuple[CanonicalWSTGStrategyDef, ...] = (
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-INPV-05",
        title="Testing for SQL Injection",
        target_cwes=("CWE-89", "CWE-564", "CWE-943"),
        techniques=("TECH-ERROR_BASED", "TECH-BLIND", "TECH-TIME_BASED"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE", "ORACLE-EXTERNAL-INTERACTION"),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-JSON-BODY"),
        description="Verify whether user-supplied input alters SQL syntax execution through error, boolean differential, or time delays.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-INPV-01",
        title="Testing for Reflected Cross Site Scripting",
        target_cwes=("CWE-79", "CWE-80"),
        techniques=("TECH-OUT_OF_BAND", "TECH-BLIND"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-HTTP-HEADER"),
        description="Verify whether unencoded user input is reflected into the HTML DOM and executed within client user context.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-INPV-12",
        title="Testing for Directory Traversal / File Include",
        target_cwes=("CWE-22", "CWE-23", "CWE-35"),
        techniques=("TECH-BLIND", "TECH-ERROR_BASED"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-QUERY-PARAMETER",),
        description="Verify whether path traversal sequences allow unauthorized access to files on the host file system.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-INPV-11",
        title="Testing for Command Injection",
        target_cwes=("CWE-78", "CWE-88", "CWE-77", "CWE-94"),
        techniques=("TECH-TIME_BASED", "TECH-OUT_OF_BAND", "TECH-ERROR_BASED"),
        channels=("CHANNEL-HTTP", "CHANNEL-DNS"),
        oracles=("ORACLE-RESPONSE", "ORACLE-EXTERNAL-INTERACTION"),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-JSON-BODY"),
        description="Verify whether operating system commands or code directives can be injected into execution sinks.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-INPV-19",
        title="Testing for Server-Side Request Forgery",
        target_cwes=("CWE-918",),
        techniques=("TECH-OUT_OF_BAND", "TECH-BLIND"),
        channels=("CHANNEL-DNS", "CHANNEL-HTTP"),
        oracles=("ORACLE-EXTERNAL-INTERACTION",),
        input_surfaces=("INPUT-HTTP-HEADER", "INPUT-JSON-BODY", "INPUT-QUERY-PARAMETER"),
        description="Verify whether backend servers can be coerced into initiating unintended requests to internal or external destinations.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-ATHN-06",
        title="Testing for Weak or Hardcoded Credentials",
        target_cwes=("CWE-798", "CWE-259", "CWE-321", "CWE-1391"),
        techniques=("TECH-BLIND", "TECH-ERROR_BASED"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-JSON-BODY"),
        description="Verify whether administrative or service access can be obtained using vendor-default or hardcoded credentials.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-INPV-07",
        title="Testing for XML Injection (XXE)",
        target_cwes=("CWE-611", "CWE-827"),
        techniques=("TECH-OUT_OF_BAND",),
        channels=("CHANNEL-DNS", "CHANNEL-HTTP"),
        oracles=("ORACLE-EXTERNAL-INTERACTION",),
        input_surfaces=("INPUT-JSON-BODY", "INPUT-QUERY-PARAMETER"),
        description="Verify whether external XML entities can be resolved to achieve local file disclosure or out-of-band SSRF.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-INPV-04",
        title="Testing for Arbitrary File Upload / Overwrite",
        target_cwes=("CWE-434", "CWE-436", "CWE-1090", "CWE-356", "CWE-73"),
        techniques=("TECH-BLIND", "TECH-ERROR_BASED"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-MULTIPART-FORM", "INPUT-QUERY-PARAMETER"),
        description="Verify whether unrestricted file upload or insufficient path validation allows arbitrary file upload or overwrite on the server.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-ATHZ-02",
        title="Testing for Insecure Direct Object References (IDOR) & Broken Access Control",
        target_cwes=("CWE-639", "CWE-862", "CWE-863", "CWE-284", "CWE-285", "CWE-732"),
        techniques=("TECH-BLIND", "TECH-ERROR_BASED"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-JSON-BODY", "INPUT-HTTP-HEADER"),
        description="Verify whether unauthorized access to sensitive records or administrative actions can be achieved through user parameter tampering or missing authorization checks.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-ATHN-04",
        title="Testing for Bypassing Authentication Schema",
        target_cwes=("CWE-287", "CWE-306", "CWE-288", "CWE-289", "CWE-290", "CWE-307"),
        techniques=("TECH-BLIND", "TECH-ERROR_BASED"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-JSON-BODY", "INPUT-HTTP-HEADER", "INPUT-COOKIE"),
        description="Verify whether critical endpoints can be accessed without valid credentials through parameter tampering, route manipulation, or missing authentication gates.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-CLNT-09",
        title="Testing for Cross-Site Request Forgery (CSRF)",
        target_cwes=("CWE-352",),
        techniques=("TECH-BLIND",),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-JSON-BODY", "INPUT-MULTIPART-FORM"),
        description="Verify whether state-changing operations can be executed on behalf of an authenticated victim without CSRF token validation.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-INPV-18",
        title="Testing for Server-Side Template Injection (SSTI)",
        target_cwes=("CWE-1336", "CWE-94", "CWE-95"),
        techniques=("TECH-ERROR_BASED", "TECH-TIME_BASED", "TECH-BLIND"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-JSON-BODY", "INPUT-HTTP-HEADER"),
        description="Verify whether template engine expressions can be evaluated dynamically on the server leading to arbitrary code execution.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-APIT-01",
        title="Testing for Insecure Deserialization & Mass Assignment",
        target_cwes=("CWE-502", "CWE-915"),
        techniques=("TECH-OUT_OF_BAND", "TECH-ERROR_BASED", "TECH-TIME_BASED"),
        channels=("CHANNEL-HTTP", "CHANNEL-DNS"),
        oracles=("ORACLE-RESPONSE", "ORACLE-EXTERNAL-INTERACTION"),
        input_surfaces=("INPUT-JSON-BODY", "INPUT-XML-BODY", "INPUT-COOKIE", "INPUT-QUERY-PARAMETER"),
        description="Verify whether untrusted serialized objects or unvalidated parameter assignments can lead to remote code execution or state alteration.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-INFO-02",
        title="Testing for Sensitive Information Disclosure & Directory Listing",
        target_cwes=("CWE-200", "CWE-209", "CWE-548", "CWE-215"),
        techniques=("TECH-BLIND", "TECH-ERROR_BASED"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-HTTP-HEADER"),
        description="Verify whether application endpoints or verbose error handlers expose sensitive data, internal paths, or credentials to unauthorized users.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-CRYP-01",
        title="Testing for Cryptographic Failures & Cleartext Transmission",
        target_cwes=("CWE-327", "CWE-319", "CWE-311", "CWE-312", "CWE-330", "CWE-338"),
        techniques=("TECH-BLIND",),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-HTTP-HEADER"),
        description="Verify whether weak cryptographic ciphers, insecure randomness, or cleartext channels are used for sensitive information.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-HOST-01",
        title="Testing for Container Breakout & Host Isolation Breach",
        target_cwes=("CWE-403", "CWE-269", "CWE-250"),
        techniques=("TECH-BLIND", "TECH-ERROR_BASED"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-RAW-SOCKET"),
        description="Verify whether leaked host file descriptors, misconfigured privileges, or runtime vulnerabilities allow escaping guest container isolation into host namespace.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-MEM-01",
        title="Testing for Memory Corruption & Buffer Overflow",
        target_cwes=("CWE-787", "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-416", "CWE-476", "CWE-190"),
        techniques=("TECH-ERROR_BASED", "TECH-BLIND", "TECH-FUZZING"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-QUERY-PARAMETER", "INPUT-JSON-BODY", "INPUT-RAW-SOCKET"),
        description="Verify whether malformed lengths, unbounded copies, or integer overflows corrupt program memory leading to denial of service or code execution.",
    ),
    CanonicalWSTGStrategyDef(
        wstg_id="WSTG-APIT-02",
        title="Testing for Resource Exhaustion & Algorithmic Denial of Service",
        target_cwes=("CWE-400", "CWE-407", "CWE-770", "CWE-730", "CWE-1245"),
        techniques=("TECH-FUZZING", "TECH-TIME_BASED", "TECH-BLIND"),
        channels=("CHANNEL-HTTP",),
        oracles=("ORACLE-RESPONSE",),
        input_surfaces=("INPUT-JSON-BODY", "INPUT-QUERY-PARAMETER"),
        description="Verify whether sending oversized payloads, deeply nested structures, or large arrays causes excessive CPU or memory consumption leading to denial of service.",
    ),
)


def canonical_wstg_source_bytes(wstg_id: str) -> bytes:
    """Return the exact curated source bytes represented by ``wstg_id``.

    The canonical catalog is a maintained semantic projection, not a verbatim
    mirror of an OWASP page.  Keeping the bytes that are hashed into the graph
    makes that distinction explicit and lets provenance replay verify the
    digest instead of pointing at a digest with no object behind it.
    """
    for definition in CANONICAL_WSTG_STRATEGIES:
        if definition.wstg_id == wstg_id:
            return f"# {definition.title}\n\n{definition.description}\n".encode("utf-8")
    raise KeyError(f"unknown canonical WSTG id: {wstg_id}")


def store_canonical_wstg_snapshots(snapshot_store: SnapshotStore) -> dict[str, str]:
    """Persist every canonical WSTG source object and return its digest index."""
    digests: dict[str, str] = {}
    for definition in CANONICAL_WSTG_STRATEGIES:
        digest = snapshot_store.put(canonical_wstg_source_bytes(definition.wstg_id))
        digests[definition.wstg_id] = digest
    return digests


TECHNIQUE_METADATA: dict[str, dict[str, Any]] = {
    "TECH-ERROR_BASED": {"name": "ErrorBased", "aliases": ["error-based", "error based"]},
    "TECH-BLIND": {"name": "Blind", "aliases": ["blind", "inferential"]},
    "TECH-TIME_BASED": {"name": "TimeBased", "aliases": ["time-based", "time delay"]},
    "TECH-OUT_OF_BAND": {"name": "OutOfBand", "aliases": ["out-of-band", "oob", "callback"]},
    "TECH-BOOLEAN_BASED": {"name": "BooleanBased", "aliases": ["boolean-based", "boolean differential"]},
    "TECH-FUZZING": {"name": "Fuzzing", "aliases": ["fuzzing", "boundary probing"]},
}

CHANNEL_METADATA: dict[str, dict[str, Any]] = {
    "CHANNEL-HTTP": {"name": "HTTP", "aliases": ["http", "https"]},
    "CHANNEL-DNS": {"name": "DNS", "aliases": ["dns"]},
}

ORACLE_METADATA: dict[str, dict[str, Any]] = {
    "ORACLE-RESPONSE": {"name": "Response observation"},
    "ORACLE-EXTERNAL-INTERACTION": {"name": "External interaction"},
}

INPUT_SURFACE_METADATA: dict[str, dict[str, Any]] = {
    "INPUT-QUERY-PARAMETER": {"name": "Query parameter"},
    "INPUT-HTTP-HEADER": {"name": "HTTP header"},
    "INPUT-JSON-BODY": {"name": "JSON body"},
    "INPUT-MULTIPART-FORM": {"name": "Multipart form data"},
    "INPUT-XML-BODY": {"name": "XML body"},
    "INPUT-COOKIE": {"name": "HTTP cookie"},
    "INPUT-RAW-SOCKET": {"name": "Raw network socket / IPC"},
}

CANONICAL_CONSTRAINTS: dict[str, dict[str, Any]] = {
    "CONSTRAINT-REMOTE-NETWORK-REACHABLE": {
        "name": "Remote Network Reachable",
        "description": "Target host and vulnerable port must be reachable over the network.",
        "expression": '{"kind":"network","key":"remote_accessible","equals":true}',
    },
    "CONSTRAINT-HTTP-SERVICE-REACHABLE": {
        "name": "HTTP/HTTPS Service Accessible",
        "description": "Web application service must be accepting HTTP/HTTPS requests.",
        "expression": '{"kind":"network","key":"http_accessible","equals":true}',
    },
    "CONSTRAINT-FTP-SERVICE-REACHABLE": {
        "name": "FTP Service Accessible",
        "description": "FTP daemon must be active and accepting connections.",
        "expression": '{"kind":"network","key":"ftp_accessible","equals":true}',
    },
    "CONSTRAINT-UNAUTHENTICATED-ACCESS": {
        "name": "Unauthenticated Access",
        "description": "Target endpoint or service permits interaction without prior credentials.",
        "expression": '{"kind":"authentication","key":"unauthenticated","equals":true}',
    },
    "CONSTRAINT-SQL-BACKEND": {
        "name": "SQL Database Backend Active",
        "description": "Backend database is an active relational SQL engine.",
        "expression": '{"kind":"configuration","key":"sql_backend","equals":true}',
    },
    "CONSTRAINT-COMMAND-EXECUTION-PRIVILEGE": {
        "name": "OS Command Execution Enabled",
        "description": "System shell or execution subsystem is reachable from process context.",
        "expression": '{"kind":"feature","key":"command_exec","equals":true}',
    },
    "CONSTRAINT-AUTHENTICATED-SESSION": {
        "name": "Authenticated User Session",
        "description": "Target operation requires an established user or victim session.",
        "expression": '{"kind":"authentication","key":"authenticated_session","equals":true}',
    },
    "CONSTRAINT-LOCAL-PROCESS-EXECUTION": {
        "name": "Local Process / Host Execution",
        "description": "Attacker has local process invocation or host execution privileges.",
        "expression": '{"kind":"feature","key":"local_exec","equals":true}',
    },
    "CONSTRAINT-CONTAINER-ENVIRONMENT": {
        "name": "Containerized Runtime Environment",
        "description": "Target software executes within a guest container isolation boundary.",
        "expression": '{"kind":"environment","key":"containerized","equals":true}',
    },
}


def build_canonical_wstg_nodes_and_edges(
    cwe_ids: set[str],
    *,
    retrieved_at: datetime | None = None,
    source_release: str = "v4.2",
    snapshot_store: SnapshotStore | None = None,
) -> tuple[list[GraphNode], list[GraphEdge]]:
    """Build all GraphNode and GraphEdge instances for the canonical WSTG catalog."""
    retrieved = retrieved_at or datetime.now(timezone.utc)
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    known_node_ids: set[str] = set()

    # Pre-populate taxonomy nodes
    for tech_id, meta in TECHNIQUE_METADATA.items():
        if tech_id not in known_node_ids:
            tech = Technique(technique_id=tech_id, name=meta["name"], aliases=tuple(meta.get("aliases", [])))
            nodes.append(GraphNode(label="Technique", node_id=tech_id, props=tech.model_dump(mode="json")))
            known_node_ids.add(tech_id)

    for chan_id, meta in CHANNEL_METADATA.items():
        if chan_id not in known_node_ids:
            nodes.append(GraphNode(label="CallbackChannel", node_id=chan_id, props={"channel_id": chan_id, "name": meta["name"], "aliases": meta.get("aliases", [])}))
            known_node_ids.add(chan_id)

    for oracle_id, meta in ORACLE_METADATA.items():
        if oracle_id not in known_node_ids:
            oracle = Oracle(oracle_id=oracle_id, name=meta["name"])
            nodes.append(GraphNode(label="Oracle", node_id=oracle_id, props=oracle.model_dump(mode="json")))
            known_node_ids.add(oracle_id)

    for inp_id, meta in INPUT_SURFACE_METADATA.items():
        if inp_id not in known_node_ids:
            inp = InputSurface(input_surface_id=inp_id, name=meta["name"])
            nodes.append(GraphNode(label="InputSurface", node_id=inp_id, props=inp.model_dump(mode="json")))
            known_node_ids.add(inp_id)

    for constraint_id, meta in CANONICAL_CONSTRAINTS.items():
        if constraint_id not in known_node_ids:
            nodes.append(
                GraphNode(
                    label="ApplicabilityConstraint",
                    node_id=constraint_id,
                    props={
                        "constraint_id": constraint_id,
                        "name": meta["name"],
                        "description": meta["description"],
                        "expression": meta["expression"],
                    },
                )
            )
            known_node_ids.add(constraint_id)

    for defn in CANONICAL_WSTG_STRATEGIES:
        source_content = canonical_wstg_source_bytes(defn.wstg_id)
        digest = f"sha256:{hashlib.sha256(source_content).hexdigest()}"
        if snapshot_store is not None:
            stored_digest = snapshot_store.put(source_content)
            if stored_digest != digest:
                raise ValueError(
                    f"canonical WSTG snapshot digest mismatch for {defn.wstg_id}"
                )
        source_url = f"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/{defn.wstg_id}"

        strategy = TestStrategy(strategy_id=f"TSTRAT-{defn.wstg_id}", name=defn.title, source_kind="wstg")
        case = WSTGCase(wstg_id=defn.wstg_id, title=defn.title, source_release=source_release, source_snapshot_digest=digest)
        evidence_id = _stable_id("EVID-WSTG", defn.wstg_id, digest)
        evidence = Evidence(evidence_id=evidence_id, kind="wstg_markdown", content_digest=digest, retrieved_at=retrieved, source_url=source_url)

        if defn.wstg_id not in known_node_ids:
            nodes.append(GraphNode(label="WSTGCase", node_id=defn.wstg_id, props={**case.model_dump(mode="json"), "source_url": source_url, "retrieved_at": retrieved.isoformat()}))
            known_node_ids.add(defn.wstg_id)

        if strategy.strategy_id not in known_node_ids:
            nodes.append(GraphNode(label="TestStrategy", node_id=strategy.strategy_id, props=strategy.model_dump(mode="json")))
            known_node_ids.add(strategy.strategy_id)

        if evidence_id not in known_node_ids:
            nodes.append(GraphNode(label="Evidence", node_id=evidence_id, props=evidence.model_dump(mode="json", exclude_none=True)))
            known_node_ids.add(evidence_id)

        edges.append(GraphEdge(
            edge_id=_stable_id("EDGE-DESCRIBES", defn.wstg_id, strategy.strategy_id),
            edge_type="DESCRIBES",
            subject_id=defn.wstg_id,
            object_id=strategy.strategy_id,
            props={"source_snapshot_digest": digest, "locator": "/", "evidence_id": evidence_id}
        ))
        edges.append(GraphEdge(
            edge_id=_stable_id("EDGE-WSTG-SUPPORTED-BY", defn.wstg_id, evidence_id),
            edge_type="SUPPORTED_BY",
            subject_id=defn.wstg_id,
            object_id=evidence_id,
        ))

        # Links to Techniques
        for tech_id in defn.techniques:
            edges.append(GraphEdge(
                edge_id=_stable_id("EDGE-USES-TECHNIQUE", strategy.strategy_id, tech_id),
                edge_type="USES_TECHNIQUE",
                subject_id=strategy.strategy_id,
                object_id=tech_id,
                props={"source_snapshot_digest": digest, "evidence_id": evidence_id}
            ))

        # Links to Channels
        for chan_id in defn.channels:
            edges.append(GraphEdge(
                edge_id=_stable_id("EDGE-USES-CHANNEL", strategy.strategy_id, chan_id),
                edge_type="USES_CHANNEL",
                subject_id=strategy.strategy_id,
                object_id=chan_id,
                props={"source_snapshot_digest": digest, "evidence_id": evidence_id}
            ))

        # Links to Oracles
        for oracle_id in defn.oracles:
            edges.append(GraphEdge(
                edge_id=_stable_id("EDGE-USES-ORACLE", strategy.strategy_id, oracle_id),
                edge_type="USES_ORACLE",
                subject_id=strategy.strategy_id,
                object_id=oracle_id,
                props={"source_snapshot_digest": digest, "evidence_id": evidence_id}
            ))

        # Links to Input Surfaces
        for inp_id in defn.input_surfaces:
            edges.append(GraphEdge(
                edge_id=_stable_id("EDGE-APPLIES-TO", strategy.strategy_id, inp_id),
                edge_type="APPLIES_TO",
                subject_id=strategy.strategy_id,
                object_id=inp_id,
                props={"source_snapshot_digest": digest, "evidence_id": evidence_id}
            ))

        # Links to Target CWEs
        for cwe_id in defn.target_cwes:
            if cwe_id in cwe_ids:
                edges.append(GraphEdge(
                    edge_id=_stable_id("EDGE-TARGETS-WEAKNESS", strategy.strategy_id, cwe_id),
                    edge_type="TARGETS_WEAKNESS",
                    subject_id=strategy.strategy_id,
                    object_id=cwe_id,
                    props={"source": "canonical-wstg-catalog", "source_snapshot_digest": digest}
                ))

    return nodes, edges


def import_canonical_wstg_catalog(
    repository: GraphRepository,
    *,
    retrieved_at: datetime | None = None,
    snapshot_store: SnapshotStore | None = None,
) -> int:
    """Ingest the canonical WSTG testing strategies into the given repository."""
    cwe_nodes = repository.nodes("CWE")
    cwe_ids = {node.node_id for node in cwe_nodes}
    nodes, edges = build_canonical_wstg_nodes_and_edges(
        cwe_ids,
        retrieved_at=retrieved_at,
        snapshot_store=snapshot_store,
    )
    repository.atomic_write(nodes=nodes, edges=edges)
    return len(CANONICAL_WSTG_STRATEGIES)
