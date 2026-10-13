# Graph Projection Contract

Every v2 node is a `GraphEntity` with immutable `nodeId` and a semantic label
such as `CWE`, `CVE`, `WeaknessAssertion`, `Technique` or `Evidence`. Every
relationship uses `edgeId` as its identity. Its source and target are `nodeId`
values and its semantic predicate is retained as `kind` and native label.

Canonical CWE edge identity includes source release, view and any source
qualifier. This permits two `CHILD_OF` records with the same endpoint pair to
coexist without overwriting provenance. Nested properties are canonically JSON
encoded by the Neo4j adapter; Pydantic models are never passed directly.
