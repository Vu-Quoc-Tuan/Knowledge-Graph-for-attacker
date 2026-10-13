from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from schema.models import NODE_KEYS


IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class GraphNode:
    label: str
    key: str
    props: dict[str, Any]


@dataclass(frozen=True)
class GraphRelationship:
    from_label: str
    from_key: str
    from_value: Any
    rel_type: str
    to_label: str
    to_key: str
    to_value: Any
    props: dict[str, Any]


@dataclass(frozen=True)
class GraphSnapshot:
    nodes: tuple[GraphNode, ...]
    relationships: tuple[GraphRelationship, ...]


def _safe_identifier(value: str) -> str:
    if not IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"unsafe graph identifier: {value!r}")
    return value


def _node_key(label: str) -> str:
    try:
        return NODE_KEYS[label]
    except KeyError:
        raise ValueError(f"unknown node label: {label!r}") from None


def rel_record(
    from_label: str,
    from_value: Any,
    rel_type: str,
    to_label: str,
    to_value: Any,
    props: dict[str, Any],
) -> dict[str, Any]:
    """The one relationship shape every sink returns.

    Both implementations must describe an edge identically, otherwise callers
    cannot be written once and the read paths drift apart per backend.
    """
    return {
        "from_label": from_label,
        "from_key": _node_key(from_label),
        "from_value": from_value,
        "type": rel_type,
        "to_label": to_label,
        "to_key": _node_key(to_label),
        "to_value": to_value,
        "props": props,
    }


def _check_endpoint_filter(label: str | None, value: Any, side: str) -> None:
    if value is not None and label is None:
        raise ValueError(f"{side}_value requires {side}_label")


class GraphSink(ABC):
    """Write and read a property graph, in memory or in Neo4j.

    Subclasses implement five primitives. Everything above this layer --
    retrieval and scenario composition -- is written once against them, so the
    dry-run and Neo4j graphs cannot drift apart in behaviour.
    """

    @abstractmethod
    def merge_node(self, label: str, key: str, props: dict[str, Any]) -> None: ...

    @abstractmethod
    def merge_rel(
        self,
        from_label: str,
        from_key: str,
        from_value: Any,
        rel_type: str,
        to_label: str,
        to_key: str,
        to_value: Any,
        props: dict[str, Any] | None = None,
    ) -> None: ...

    @abstractmethod
    def nodes(self, label: str | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_node(self, label: str, key: str, value: Any) -> dict[str, Any] | None: ...

    @abstractmethod
    def match_rels(
        self,
        rel_type: str | None = None,
        *,
        from_label: str | None = None,
        from_value: Any = None,
        to_label: str | None = None,
        to_value: Any = None,
    ) -> list[dict[str, Any]]:
        """Relationships matching every constraint given, as `rel_record`s.

        Filtering by an endpoint value requires that endpoint's label, since
        the label determines which property carries the identity.
        """

    def relationships(self, rel_type: str | None = None) -> list[dict[str, Any]]:
        return self.match_rels(rel_type)

    def close(self) -> None:
        return None


class DryRunSink(GraphSink):
    def __init__(self) -> None:
        self._nodes: dict[tuple[str, str, Any], dict[str, Any]] = {}
        self._relationships: dict[
            tuple[str, str, Any, str, str, str, Any], dict[str, Any]
        ] = {}

    def merge_node(self, label: str, key: str, props: dict[str, Any]) -> None:
        _safe_identifier(label)
        _safe_identifier(key)
        if key not in props:
            raise ValueError(f"node {label} is missing identity property {key}")
        identity = (label, key, props[key])
        current = self._nodes.setdefault(identity, {"_label": label})
        current.update(props)

    def merge_rel(
        self,
        from_label: str,
        from_key: str,
        from_value: Any,
        rel_type: str,
        to_label: str,
        to_key: str,
        to_value: Any,
        props: dict[str, Any] | None = None,
    ) -> None:
        for identifier in (from_label, from_key, rel_type, to_label, to_key):
            _safe_identifier(identifier)
        from_identity = (from_label, from_key, from_value)
        to_identity = (to_label, to_key, to_value)
        if from_identity not in self._nodes or to_identity not in self._nodes:
            raise ValueError(
                f"cannot create {rel_type}: missing endpoint "
                f"{from_identity if from_identity not in self._nodes else to_identity}"
            )
        identity = (
            from_label,
            from_key,
            from_value,
            rel_type,
            to_label,
            to_key,
            to_value,
        )
        rel = self._relationships.setdefault(
            identity,
            {
                "from_label": from_label,
                "from_value": from_value,
                "type": rel_type,
                "to_label": to_label,
                "to_value": to_value,
                "props": {},
            },
        )
        rel["props"].update(props or {})

    def nodes(self, label: str | None = None) -> list[dict[str, Any]]:
        values = self._nodes.values()
        if label is not None:
            values = (node for node in values if node["_label"] == label)
        return [dict(node) for node in values]

    def get_node(self, label: str, key: str, value: Any) -> dict[str, Any] | None:
        node = self._nodes.get((label, key, value))
        return dict(node) if node else None

    def match_rels(
        self,
        rel_type: str | None = None,
        *,
        from_label: str | None = None,
        from_value: Any = None,
        to_label: str | None = None,
        to_value: Any = None,
    ) -> list[dict[str, Any]]:
        _check_endpoint_filter(from_label, from_value, "from")
        _check_endpoint_filter(to_label, to_value, "to")
        matched = []
        for rel in self._relationships.values():
            if rel_type is not None and rel["type"] != rel_type:
                continue
            if from_label is not None and rel["from_label"] != from_label:
                continue
            if from_value is not None and rel["from_value"] != from_value:
                continue
            if to_label is not None and rel["to_label"] != to_label:
                continue
            if to_value is not None and rel["to_value"] != to_value:
                continue
            matched.append(
                rel_record(
                    rel["from_label"],
                    rel["from_value"],
                    rel["type"],
                    rel["to_label"],
                    rel["to_value"],
                    dict(rel["props"]),
                )
            )
        return matched

    def snapshot(self) -> GraphSnapshot:
        nodes = tuple(
            GraphNode(
                label=label,
                key=key,
                props={
                    prop: value
                    for prop, value in node.items()
                    if prop != "_label"
                },
            )
            for (label, key, _value), node in sorted(
                self._nodes.items(),
                key=lambda item: tuple(map(str, item[0])),
            )
        )
        relationships = tuple(
            GraphRelationship(
                from_label=identity[0],
                from_key=identity[1],
                from_value=identity[2],
                rel_type=identity[3],
                to_label=identity[4],
                to_key=identity[5],
                to_value=identity[6],
                props=dict(record["props"]),
            )
            for identity, record in sorted(
                self._relationships.items(),
                key=lambda item: tuple(map(str, item[0])),
            )
        )
        return GraphSnapshot(
            nodes=nodes,
            relationships=relationships,
        )


class Neo4jSink(GraphSink):
    def __init__(self, uri: str, user: str, password: str) -> None:
        from neo4j import GraphDatabase

        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        try:
            self.driver.verify_connectivity()
        except Exception:
            # A failed optional test-backend probe must not leak the driver.
            # Neo4j warns from Driver.__del__, and `-W error` correctly turns
            # that resource leak into a suite failure.
            self.driver.close()
            raise

    def merge_node(self, label: str, key: str, props: dict[str, Any]) -> None:
        label = _safe_identifier(label)
        key = _safe_identifier(key)
        if key not in props:
            raise ValueError(f"node {label} is missing identity property {key}")
        query = f"MERGE (n:`{label}` {{`{key}`: $identity}}) SET n += $props"
        self.run_write(query, identity=props[key], props=props)

    def merge_rel(
        self,
        from_label: str,
        from_key: str,
        from_value: Any,
        rel_type: str,
        to_label: str,
        to_key: str,
        to_value: Any,
        props: dict[str, Any] | None = None,
    ) -> None:
        values = [from_label, from_key, rel_type, to_label, to_key]
        from_label, from_key, rel_type, to_label, to_key = map(
            _safe_identifier, values
        )
        query = (
            f"MATCH (a:`{from_label}` {{`{from_key}`: $from_value}}) "
            f"MATCH (b:`{to_label}` {{`{to_key}`: $to_value}}) "
            f"MERGE (a)-[r:`{rel_type}`]->(b) SET r += $props "
            "RETURN count(r) AS matched"
        )
        records = self.run_write(
            query,
            from_value=from_value,
            to_value=to_value,
            props=props or {},
        )
        if not records or records[0]["matched"] < 1:
            raise ValueError(f"cannot create {rel_type}: missing endpoint")

    def nodes(self, label: str | None = None) -> list[dict[str, Any]]:
        if label:
            label = _safe_identifier(label)
            query = f"MATCH (n:`{label}`) RETURN n, labels(n)[0] AS label"
        else:
            query = "MATCH (n) RETURN n, labels(n)[0] AS label"
        return [
            {**dict(row["n"]), "_label": row["label"]}
            for row in self.run_read(query)
        ]

    def get_node(self, label: str, key: str, value: Any) -> dict[str, Any] | None:
        label = _safe_identifier(label)
        key = _safe_identifier(key)
        query = (
            f"MATCH (n:`{label}` {{`{key}`: $value}}) "
            "RETURN properties(n) AS props, labels(n)[0] AS label"
        )
        rows = self.run_read(query, value=value)
        if not rows:
            return None
        return {**rows[0]["props"], "_label": rows[0]["label"]}

    def match_rels(
        self,
        rel_type: str | None = None,
        *,
        from_label: str | None = None,
        from_value: Any = None,
        to_label: str | None = None,
        to_value: Any = None,
    ) -> list[dict[str, Any]]:
        _check_endpoint_filter(from_label, from_value, "from")
        _check_endpoint_filter(to_label, to_value, "to")
        params: dict[str, Any] = {}
        from_pattern = f":`{_safe_identifier(from_label)}`" if from_label else ""
        to_pattern = f":`{_safe_identifier(to_label)}`" if to_label else ""
        type_filter = ""
        if rel_type:
            _safe_identifier(rel_type)
            params["rel_type"] = rel_type
            type_filter = " WHERE type(r) = $rel_type"
        if from_value is not None:
            if from_label is None:
                raise ValueError("from_label is required when from_value is set")
            key = _safe_identifier(_node_key(from_label))
            from_pattern += f" {{`{key}`: $from_value}}"
            params["from_value"] = from_value
        if to_value is not None:
            if to_label is None:
                raise ValueError("to_label is required when to_value is set")
            key = _safe_identifier(_node_key(to_label))
            to_pattern += f" {{`{key}`: $to_value}}"
            params["to_value"] = to_value
        query = (
            f"MATCH (a{from_pattern})-[r]->(b{to_pattern})"
            f"{type_filter} "
            "RETURN labels(a)[0] AS from_label, properties(a) AS from_props, "
            "type(r) AS type, labels(b)[0] AS to_label, "
            "properties(b) AS to_props, properties(r) AS props"
        )
        return [
            rel_record(
                row["from_label"],
                row["from_props"].get(_node_key(row["from_label"])),
                row["type"],
                row["to_label"],
                row["to_props"].get(_node_key(row["to_label"])),
                row["props"],
            )
            for row in self.run_read(query, **params)
        ]

    @staticmethod
    def _run_transaction(
        tx: Any,
        query: str,
        params: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return [dict(record) for record in tx.run(query, **params)]

    def run_read(self, query: str, **params: Any) -> list[dict[str, Any]]:
        """Run a read query in a managed transaction with driver retries."""
        with self.driver.session() as session:
            return session.execute_read(self._run_transaction, query, params)

    def run_write(self, query: str, **params: Any) -> list[dict[str, Any]]:
        """Run a write query in a managed transaction with driver retries."""
        with self.driver.session() as session:
            return session.execute_write(self._run_transaction, query, params)

    @staticmethod
    def _replace_transaction(tx: Any, snapshot: GraphSnapshot) -> None:
        tx.run("MATCH (n) DETACH DELETE n").consume()
        for node in snapshot.nodes:
            label = _safe_identifier(node.label)
            key = _safe_identifier(node.key)
            if key not in node.props:
                raise ValueError(
                    f"node {label} is missing identity property {key}"
                )
            tx.run(
                f"MERGE (n:`{label}` {{`{key}`: $identity}}) "
                "SET n = $props",
                identity=node.props[key],
                props=node.props,
            ).consume()

        for relationship in snapshot.relationships:
            from_label = _safe_identifier(relationship.from_label)
            from_key = _safe_identifier(relationship.from_key)
            rel_type = _safe_identifier(relationship.rel_type)
            to_label = _safe_identifier(relationship.to_label)
            to_key = _safe_identifier(relationship.to_key)
            record = tx.run(
                f"MATCH (a:`{from_label}` "
                f"{{`{from_key}`: $from_value}}) "
                f"MATCH (b:`{to_label}` {{`{to_key}`: $to_value}}) "
                f"MERGE (a)-[r:`{rel_type}`]->(b) "
                "SET r = $props RETURN count(r) AS matched",
                from_value=relationship.from_value,
                to_value=relationship.to_value,
                props=relationship.props,
            ).single()
            if record is None or record["matched"] != 1:
                raise ValueError(
                    f"cannot create {rel_type}: missing endpoint"
                )

    def replace_graph(self, snapshot: GraphSnapshot) -> None:
        """Replace all graph data in one rollback-capable transaction."""

        with self.driver.session() as session:
            session.execute_write(self._replace_transaction, snapshot)

    def _apply_script(self, path: str | Path) -> None:
        source = Path(path).read_text(encoding="utf-8")
        for statement in source.split(";"):
            statement = statement.strip()
            if statement:
                self.run_write(statement)

    def apply_schema(self, path: str | Path) -> None:
        self._apply_script(path)

    def apply_migration(self, path: str | Path) -> None:
        self._apply_script(path)

    def has_legacy_weaknesses(self) -> bool:
        rows = self.run_read(
            "MATCH (w:Weakness) "
            "WHERE w.weaknessId IS NULL "
            "RETURN count(w) AS count"
        )
        return bool(rows and rows[0]["count"])

    def close(self) -> None:
        self.driver.close()
