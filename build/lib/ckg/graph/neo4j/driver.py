"""Neo4j implementation of the v2 repository contract.

The adapter deliberately uses a stable `GraphEntity.nodeId` identity and an
explicit `CKG_REL.edgeId`.  Native relationship type is not used as identity,
because the same canonical predicate may occur in more than one view/release.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from ckg.graph.models import BoundedNeighborhood, GraphEdge, GraphNode, VulnerabilitySearchMatch
from ckg.graph.ports import GraphRepository
from ckg.graph.search import merge_vulnerability_matches, normalize_search_term, product_match


_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_SCALAR = str | int | float | bool | None
_JSON_BUNDLE_KEY = "ckgV2Json"
_NODE_METADATA_KEYS = frozenset({"nodeId", "kind"})
_EDGE_METADATA_KEYS = frozenset({"edgeId", "kind"})


def _safe_identifier(value: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"unsafe Neo4j identifier: {value!r}")
    return value


def _is_neo4j_value(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _is_neo4j_list(value: Any) -> bool:
    return isinstance(value, (list, tuple)) and all(
        isinstance(item, (str, int, float, bool)) for item in value
    )


def serialize_properties(
    props: dict[str, Any], *, reserved_keys: frozenset[str] = frozenset()
) -> dict[str, _SCALAR | list[_SCALAR]]:
    """Encode domain properties into Neo4j's flat property model reversibly.

    Neo4j cannot store maps or lists of maps.  Earlier code converted every
    map to a ``<name>Json`` property, which both broke list-of-evidence-spans
    and changed the public graph contract on read.  Keep native scalar values
    queryable, and place every nested value (and storage-metadata collision)
    in one versioned JSON bundle.  ``deserialize_properties`` restores the
    exact caller-facing shape.
    """

    encoded: dict[str, _SCALAR | list[_SCALAR]] = {}
    nested: dict[str, Any] = {}
    for key, value in props.items():
        _safe_identifier(key)
        if key == _JSON_BUNDLE_KEY or key in reserved_keys:
            nested[key] = value
        elif _is_neo4j_value(value):
            encoded[key] = value
        elif _is_neo4j_list(value):
            encoded[key] = list(value)
        else:
            nested[key] = value
    if nested:
        try:
            encoded[_JSON_BUNDLE_KEY] = json.dumps(
                nested, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
        except (TypeError, ValueError) as error:
            raise ValueError("properties contain values that cannot be JSON encoded") from error
    return encoded


def deserialize_properties(
    props: dict[str, Any], *, metadata_keys: frozenset[str]
) -> dict[str, Any]:
    """Restore graph properties written by :func:`serialize_properties`.

    The bundle is intentionally fail-closed: a malformed or colliding bundle
    is storage corruption, not a reason to silently return altered evidence.
    """

    direct = {
        key: value
        for key, value in props.items()
        if key not in metadata_keys and key != _JSON_BUNDLE_KEY
    }
    bundle = props.get(_JSON_BUNDLE_KEY)
    if bundle is None:
        return direct
    if not isinstance(bundle, str):
        raise ValueError("invalid Neo4j property bundle: expected JSON string")
    try:
        nested = json.loads(bundle)
    except json.JSONDecodeError as error:
        raise ValueError("invalid Neo4j property bundle: malformed JSON") from error
    if not isinstance(nested, dict) or any(not isinstance(key, str) for key in nested):
        raise ValueError("invalid Neo4j property bundle: expected JSON object")
    collisions = set(direct).intersection(nested)
    if collisions:
        raise ValueError(
            "invalid Neo4j property bundle: duplicate keys " + ", ".join(sorted(collisions))
        )
    return {**direct, **nested}


class Neo4jGraphRepository(GraphRepository):
    def __init__(self, uri: str, user: str, password: str) -> None:
        from neo4j import GraphDatabase

        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    @property
    def backend_name(self) -> str:
        return "neo4j"

    def close(self) -> None:
        self._driver.close()

    def apply_schema(self, path: str) -> None:
        """Apply idempotent v2 constraints/indexes before writing a projection."""
        with open(path, encoding="utf-8") as schema_file:
            statements = schema_file.read().split(";")
        with self._driver.session() as session:
            for statement in statements:
                if statement.strip():
                    session.run(statement).consume()

    @staticmethod
    def _write_batch(tx: Any, nodes: Iterable[GraphNode], edges: Iterable[GraphEdge]) -> None:
        node_ids: set[str] = set()
        for node in nodes:
            label = _safe_identifier(node.label)
            if node.node_id in node_ids:
                raise ValueError(f"duplicate node identity in batch: {node.node_id}")
            node_ids.add(node.node_id)
            props = {
                **serialize_properties(node.props, reserved_keys=_NODE_METADATA_KEYS),
                "nodeId": node.node_id,
                "kind": node.label,
            }
            tx.run(
                f"MERGE (n:GraphEntity:`{label}` {{nodeId: $node_id}}) SET n = $props",
                node_id=node.node_id,
                props=props,
            ).consume()
        for edge in edges:
            endpoints = tx.run(
                "MATCH (subject:GraphEntity {nodeId: $subject_id}) "
                "MATCH (object:GraphEntity {nodeId: $object_id}) "
                "RETURN subject.kind AS subject_kind, object.kind AS object_kind",
                subject_id=edge.subject_id,
                object_id=edge.object_id,
            ).single()
            if endpoints is not None and (
                (endpoints["subject_kind"] == "CWE" and endpoints["object_kind"] in {"CVE", "GHSA"})
                or (endpoints["object_kind"] == "CWE" and endpoints["subject_kind"] in {"CVE", "GHSA"})
            ):
                raise ValueError(
                    "direct vulnerability-to-CWE relation is forbidden; "
                    "use a reified WeaknessAssertion"
                )
            existing = tx.run(
                "MATCH (subject:GraphEntity)-[rel:CKG_REL {edgeId: $edge_id}]->(object:GraphEntity) "
                "RETURN rel.kind AS edge_type, subject.nodeId AS subject_id, object.nodeId AS object_id",
                edge_id=edge.edge_id,
            ).single()
            if existing is not None and (
                existing["edge_type"] != edge.edge_type
                or existing["subject_id"] != edge.subject_id
                or existing["object_id"] != edge.object_id
            ):
                raise ValueError(f"edge identity collision: {edge.edge_id}")
            props = {
                **serialize_properties(edge.props, reserved_keys=_EDGE_METADATA_KEYS),
                "edgeId": edge.edge_id,
                "kind": edge.edge_type,
            }
            record = tx.run(
                f"MATCH (subject:GraphEntity {{nodeId: $subject_id}}) "
                f"MATCH (object:GraphEntity {{nodeId: $object_id}}) "
                "MERGE (subject)-[rel:CKG_REL {edgeId: $edge_id}]->(object) "
                "SET rel = $props RETURN count(rel) AS count",
                subject_id=edge.subject_id,
                object_id=edge.object_id,
                edge_id=edge.edge_id,
                props=props,
            ).single()
            if record is None or record["count"] != 1:
                raise ValueError(f"cannot create {edge.edge_id}: missing endpoint")

    def atomic_write(self, *, nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
        with self._driver.session() as session:
            session.execute_write(self._write_batch, nodes, edges)

    @staticmethod
    def _replace(tx: Any, nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
        tx.run("MATCH (n:GraphEntity) DETACH DELETE n").consume()
        Neo4jGraphRepository._write_batch(tx, nodes, edges)

    def replace_all(self, *, nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
        with self._driver.session() as session:
            session.execute_write(self._replace, nodes, edges)

    @staticmethod
    def _replace_database(tx: Any, nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
        """Replace every node in the selected database, including legacy labels.

        This is intentionally separate from ``replace_all``: the normal v2
        operation only replaces ``GraphEntity`` nodes, while a deliberate
        database cutover must also remove leftover legacy labels and their
        relationships in the same transaction.
        """
        tx.run("MATCH (n) DETACH DELETE n").consume()
        Neo4jGraphRepository._write_database_batch(tx, nodes, edges)

    @staticmethod
    def _write_database_batch(tx: Any, nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
        """Write a fresh database with bounded UNWIND batches.

        ``_write_batch`` intentionally performs per-edge identity checks for
        normal incremental writes.  A validated full replacement has already
        checked identities and endpoints in memory, so doing one query per edge
        would make a graph cutover needlessly slow.
        """
        nodes_by_label: dict[str, list[dict[str, object]]] = defaultdict(list)
        for node in nodes:
            label = _safe_identifier(node.label)
            nodes_by_label[label].append(
                {
                    "node_id": node.node_id,
                    "props": {
                        **serialize_properties(node.props, reserved_keys=_NODE_METADATA_KEYS),
                        "nodeId": node.node_id,
                        "kind": node.label,
                    },
                }
            )
        for label, rows in sorted(nodes_by_label.items()):
            tx.run(
                f"UNWIND $rows AS row "
                f"CREATE (n:GraphEntity:`{label}` {{nodeId: row.node_id}}) "
                "SET n = row.props",
                rows=rows,
            ).consume()

        edge_rows = []
        for edge in edges:
            edge_rows.append(
                {
                    "subject_id": edge.subject_id,
                    "object_id": edge.object_id,
                    "props": {
                        **serialize_properties(edge.props, reserved_keys=_EDGE_METADATA_KEYS),
                        "edgeId": edge.edge_id,
                        "kind": edge.edge_type,
                    },
                }
            )
        if edge_rows:
            tx.run(
                "UNWIND $rows AS row "
                "MATCH (subject:GraphEntity {nodeId: row.subject_id}) "
                "MATCH (object:GraphEntity {nodeId: row.object_id}) "
                "CREATE (subject)-[rel:CKG_REL]->(object) "
                "SET rel = row.props",
                rows=edge_rows,
            ).consume()

    def replace_database(self, *, nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
        """Atomically replace the complete graph database with a v2 projection."""
        with self._driver.session() as session:
            session.execute_write(self._replace_database, nodes, edges)

    def nodes(self, label: str | None = None) -> list[GraphNode]:
        params: dict[str, Any] = {}
        filter_clause = ""
        if label is not None:
            params["node_kind"] = _safe_identifier(label)
            filter_clause = "WHERE n.kind = $node_kind "
        query = (
            "MATCH (n:GraphEntity) "
            f"{filter_clause}"
            "RETURN n.kind AS label, n.nodeId AS node_id, properties(n) AS props "
            "ORDER BY node_id"
        )
        with self._driver.session() as session:
            rows = list(session.run(query, **params))
        return [
            GraphNode(
                label=row["label"],
                node_id=row["node_id"],
                props=deserialize_properties(row["props"], metadata_keys=_NODE_METADATA_KEYS),
            )
            for row in rows
        ]

    def edges(self, edge_type: str | None = None) -> list[GraphEdge]:
        params: dict[str, Any] = {}
        filter_clause = ""
        if edge_type is not None:
            params["edge_type"] = edge_type
            filter_clause = "WHERE rel.kind = $edge_type "
        query = (
            "MATCH (subject:GraphEntity)-[rel:CKG_REL]->(object:GraphEntity) "
            f"{filter_clause}"
            "RETURN rel.kind AS edge_type, rel.edgeId AS edge_id, "
            "subject.nodeId AS subject_id, object.nodeId AS object_id, properties(rel) AS props "
            "ORDER BY edge_id"
        )
        with self._driver.session() as session:
            rows = list(session.run(query, **params))
        return [
            GraphEdge(
                edge_id=row["edge_id"],
                edge_type=row["edge_type"],
                subject_id=row["subject_id"],
                object_id=row["object_id"],
                props=deserialize_properties(row["props"], metadata_keys=_EDGE_METADATA_KEYS),
            )
            for row in rows
        ]

    def find_nodes(self, label: str, properties: dict[str, object]) -> list[GraphNode]:
        """Push exact legacy-anchor lookups into Neo4j.

        ``target_vulnerability_id`` and ``vulnerability_id`` are retained
        only for compatibility with early projections.  They must not force a
        full node export while constructing a bounded reasoning envelope.
        """
        safe_label = _safe_identifier(label)
        clauses: list[str] = []
        params: dict[str, object] = {"node_kind": safe_label}
        clauses.append("n.kind = $node_kind")
        for index, (key, value) in enumerate(sorted(properties.items())):
            safe_key = _safe_identifier(key)
            parameter = f"property_{index}"
            clauses.append(f"n.`{safe_key}` = ${parameter}")
            params[parameter] = value
        where = " AND ".join(clauses) if clauses else "true"
        query = (
            f"MATCH (n:GraphEntity) WHERE {where} "
            "RETURN n.kind AS label, n.nodeId AS node_id, properties(n) AS props "
            "ORDER BY node_id"
        )
        with self._driver.session() as session:
            rows = list(session.run(query, **params))
        return [
            GraphNode(
                label=row["label"],
                node_id=row["node_id"],
                props=deserialize_properties(row["props"], metadata_keys=_NODE_METADATA_KEYS),
            )
            for row in rows
        ]

    def nodes_by_ids(self, node_ids: frozenset[str]) -> list[GraphNode]:
        if not node_ids:
            return []
        query = (
            "MATCH (n:GraphEntity) WHERE n.nodeId IN $node_ids "
            "RETURN n.kind AS label, n.nodeId AS node_id, properties(n) AS props "
            "ORDER BY node_id"
        )
        with self._driver.session() as session:
            rows = list(session.run(query, node_ids=sorted(node_ids)))
        return [
            GraphNode(
                label=row["label"],
                node_id=row["node_id"],
                props=deserialize_properties(row["props"], metadata_keys=_NODE_METADATA_KEYS),
            )
            for row in rows
        ]

    def edges_between(
        self, node_ids: frozenset[str], *, edge_types: frozenset[str] | None = None
    ) -> list[GraphEdge]:
        if not node_ids:
            return []
        filters = ["subject.nodeId IN $node_ids", "object.nodeId IN $node_ids"]
        params: dict[str, object] = {"node_ids": sorted(node_ids)}
        if edge_types is not None:
            filters.append("rel.kind IN $edge_types")
            params["edge_types"] = sorted(edge_types)
        query = (
            "MATCH (subject:GraphEntity)-[rel:CKG_REL]->(object:GraphEntity) "
            f"WHERE {' AND '.join(filters)} "
            "RETURN rel.kind AS edge_type, rel.edgeId AS edge_id, "
            "subject.nodeId AS subject_id, object.nodeId AS object_id, properties(rel) AS props "
            "ORDER BY edge_id"
        )
        with self._driver.session() as session:
            rows = list(session.run(query, **params))
        return [
            GraphEdge(
                edge_id=row["edge_id"],
                edge_type=row["edge_type"],
                subject_id=row["subject_id"],
                object_id=row["object_id"],
                props=deserialize_properties(row["props"], metadata_keys=_EDGE_METADATA_KEYS),
            )
            for row in rows
        ]

    @staticmethod
    def _search_node(value: dict[str, Any] | None) -> GraphNode | None:
        if not value:
            return None
        return GraphNode(
            label=value["label"],
            node_id=value["node_id"],
            props=deserialize_properties(value["props"], metadata_keys=_NODE_METADATA_KEYS),
        )

    def search_vulnerabilities(
        self,
        technology: str,
        *,
        from_year: int,
        to_year: int,
        limit: int = 100,
    ) -> list[VulnerabilitySearchMatch]:
        """Search Product-backed vulnerabilities inside a bounded Cypher query."""
        normalized_term = normalize_search_term(technology)
        if not normalized_term:
            raise ValueError("technology must not be empty")
        if from_year > to_year:
            raise ValueError("from_year must be less than or equal to to_year")
        if limit < 1:
            raise ValueError("limit must be at least 1")
        query = (
            "MATCH (v:GraphEntity)-[:CKG_REL {kind: 'AFFECTS'}]->(p:GraphEntity) "
            "WHERE v.kind IN $vulnerability_labels AND p.kind = 'Product' "
            "AND all(token IN $technology_tokens WHERE "
            "toLower(coalesce(p.name, '')) CONTAINS token "
            "OR toLower(coalesce(p.package_name, '')) CONTAINS token "
            "OR toLower(coalesce(p.vendor, '')) CONTAINS token "
            "OR toLower(coalesce(properties(p)['cpe_uri'], '')) CONTAINS token "
            "OR any(alias IN coalesce(p.aliases, []) WHERE toLower(alias) CONTAINS token)) "
            "AND v.published_at >= $from_date AND v.published_at < $to_date "
            "WITH v, collect(DISTINCT p) AS products "
            "OPTIONAL MATCH (v)-[version_rel:CKG_REL {kind: 'AFFECTS_VERSION'}]->(version:GraphEntity) "
            "WHERE (coalesce(properties(version_rel)['product_ids'], []) = [] "
            "AND properties(version_rel)['product_id'] IS NULL) "
            "OR any(product IN products WHERE product.nodeId IN coalesce(properties(version_rel)['product_ids'], []) "
            "OR product.nodeId = properties(version_rel)['product_id']) "
            "WITH v, products, collect(DISTINCT version) AS versions "
            "OPTIONAL MATCH (source:GraphEntity)-[:CKG_REL {kind: 'DESCRIBES'}]->(v) "
            "WITH v, products, versions, collect(DISTINCT source) AS sources "
            "RETURN {label: v.kind, node_id: v.nodeId, props: properties(v)} AS vulnerability, "
            "[product IN products | {label: product.kind, node_id: product.nodeId, props: properties(product)}] AS products, "
            "[item IN versions WHERE item IS NOT NULL | {label: item.kind, node_id: item.nodeId, props: properties(item)}] AS versions, "
            "[item IN sources WHERE item IS NOT NULL | {label: item.kind, node_id: item.nodeId, props: properties(item)}] AS sources "
            "ORDER BY v.published_at DESC, v.nodeId "
            "LIMIT $candidate_limit"
        )
        params = {
            "vulnerability_labels": ["CVE", "GHSA"],
            "technology_tokens": normalized_term.split(),
            "from_date": f"{from_year:04d}-01-01T00:00:00+00:00",
            "to_date": f"{to_year + 1:04d}-01-01T00:00:00+00:00",
            # Alias folding happens after the query, so keep a small safety
            # margin without allowing an unbounded result set.
            "candidate_limit": min(max(limit * 4, limit), 1000),
        }
        with self._driver.session() as session:
            rows = list(session.run(query, **params))
        matches: list[VulnerabilitySearchMatch] = []
        for row in rows:
            vulnerability = self._search_node(row["vulnerability"])
            if vulnerability is None:
                continue
            products = tuple(
                node for node in (self._search_node(item) for item in row["products"]) if node is not None
            )
            versions = tuple(
                node for node in (self._search_node(item) for item in row["versions"]) if node is not None
            )
            sources = tuple(
                node for node in (self._search_node(item) for item in row["sources"]) if node is not None
            )
            product_scores = [product_match(product.props, normalized_term) for product in products]
            best_product_score = max(
                (score for score in product_scores if score is not None),
                default=None,
            )
            if best_product_score is None:
                continue
            matches.append(
                VulnerabilitySearchMatch(
                    vulnerability,
                    products,
                    versions,
                    sources,
                    relevance=best_product_score[0],
                    match_reason=best_product_score[1],
                )
            )
        return merge_vulnerability_matches(matches, limit=limit)

    @staticmethod
    def _read_bounded_neighborhood(
        transaction: Any,
        root_query: str,
        path_query: str,
        nodes_query: str,
        edges_query: str,
        root_id: str,
        edge_type_list: list[str],
        max_paths: int,
        max_nodes: int,
        timeout_seconds: float,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool] | None:
        """Read a bounded neighbourhood in a managed, retryable transaction."""
        from neo4j import Query

        def timed_run(query: str, **parameters: Any) -> Any:
            """Run a bounded read across Neo4j driver timeout API variants.

            Recent drivers accept ``Query(timeout=...)`` only through
            ``Session.run``; managed transaction ``run`` accepts the Cypher
            string but rejects the Query object.  Keep the retryable managed
            transaction and fall back to the transaction-compatible form when
            that API is in use.
            """
            try:
                return transaction.run(Query(query, timeout=timeout_seconds), **parameters)
            except TypeError as error:
                if "Query object is only supported for session.run" not in str(error):
                    raise
                return transaction.run(query, **parameters)

        root_row = timed_run(root_query, root_id=root_id).single()
        if root_row is None:
            return None

        path_rows = [
            dict(row)
            for row in timed_run(
                path_query,
                root_id=root_id,
                edge_types=edge_type_list,
                path_limit=max_paths + 1,
            )
        ]
        node_ids = [root_id]
        seen_node_ids = {root_id}
        for row in path_rows[:max_paths]:
            for node_id in row["node_ids"]:
                if node_id in seen_node_ids:
                    continue
                seen_node_ids.add(node_id)
                node_ids.append(node_id)
        truncated = len(path_rows) > max_paths or len(node_ids) > max_nodes
        selected_ids = tuple(node_ids[:max_nodes])
        node_rows = [
            dict(row)
            for row in timed_run(nodes_query, node_ids=selected_ids)
        ]
        edge_rows = [
            dict(row)
            for row in timed_run(
                edges_query,
                node_ids=selected_ids,
                edge_types=edge_type_list,
            )
        ]
        return node_rows, edge_rows, truncated

    def bounded_neighborhood(
        self,
        root_id: str,
        *,
        edge_types: frozenset[str],
        max_depth: int,
        max_nodes: int,
        max_paths: int,
        timeout_seconds: float,
    ) -> BoundedNeighborhood | None:
        """Fetch only a bounded whitelist neighbourhood inside Neo4j.

        Path enumeration has an independent cap and explicit transaction
        timeout.  The reasoner still applies per-plane caps and temporal
        visibility to this returned envelope.
        """
        if max_depth < 1 or max_nodes < 1 or max_paths < 1:
            return BoundedNeighborhood((), (), truncated=True)
        edge_type_list = sorted(edge_types)
        root_query = (
            "MATCH (node:GraphEntity {nodeId: $root_id}) "
            "RETURN node.kind AS label, node.nodeId AS node_id, properties(node) AS props"
        )
        path_query = (
            "MATCH (root:GraphEntity {nodeId: $root_id}) "
            f"MATCH path=(root)-[rels:CKG_REL*1..{max_depth}]-(candidate:GraphEntity) "
            "WHERE ALL(rel IN rels WHERE rel.kind IN $edge_types) "
            # Preserve shallow path prefixes before applying the node cap.
            # Sorting a set of every path node could retain leaves while
            # discarding their sole intermediate assertion, producing a
            # disconnected root-only graph after edge filtering.
            "WITH path ORDER BY length(path), reduce(key = '', node IN nodes(path) | key + '|' + node.nodeId) "
            "LIMIT $path_limit "
            "RETURN [node IN nodes(path) | node.nodeId] AS node_ids"
        )
        nodes_query = (
            "MATCH (node:GraphEntity) WHERE node.nodeId IN $node_ids "
            "RETURN node.kind AS label, node.nodeId AS node_id, properties(node) AS props "
            "ORDER BY node_id"
        )
        edges_query = (
            "MATCH (subject:GraphEntity)-[rel:CKG_REL]->(object:GraphEntity) "
            "WHERE subject.nodeId IN $node_ids AND object.nodeId IN $node_ids AND rel.kind IN $edge_types "
            "RETURN rel.kind AS edge_type, rel.edgeId AS edge_id, subject.nodeId AS subject_id, object.nodeId AS object_id, properties(rel) AS props "
            "ORDER BY edge_id"
        )
        with self._driver.session() as session:
            result = session.execute_read(
                self._read_bounded_neighborhood,
                root_query,
                path_query,
                nodes_query,
                edges_query,
                root_id,
                edge_type_list,
                max_paths,
                max_nodes,
                timeout_seconds,
            )
        if result is None:
            return None
        node_rows, edge_rows, truncated = result
        nodes = tuple(
            GraphNode(
                label=row["label"],
                node_id=row["node_id"],
                props=deserialize_properties(row["props"], metadata_keys=_NODE_METADATA_KEYS),
            )
            for row in node_rows
        )
        edges = tuple(
            GraphEdge(
                edge_id=row["edge_id"],
                edge_type=row["edge_type"],
                subject_id=row["subject_id"],
                object_id=row["object_id"],
                props=deserialize_properties(row["props"], metadata_keys=_EDGE_METADATA_KEYS),
            )
            for row in edge_rows
        )
        return BoundedNeighborhood(nodes, edges, truncated=truncated)
