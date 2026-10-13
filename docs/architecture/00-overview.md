# Evolving Vulnerability CKG Overview

The system keeps MITRE CWE as an immutable canonical backbone and places all
reported, extracted, observed and inferred knowledge beside it as versioned,
evidence-grounded claims. A vulnerability is anchored through independent
weakness, technique, context, constraint and evidence facets. No consumer may
reduce that representation to one CWE label.

The initial production path is offline and deterministic:

```text
pinned source bytes -> evidence/span -> typed assertion -> graph projection
```

Later paths add extraction, historical retrieval, bounded local subgraphs and
scenario discovery. They produce candidates with explicit unknowns. They do
not mutate canonical source nodes and do not execute probes.

Legacy registry/event files are migration inputs only; they are not a second
runtime graph or UI. The v2 graph is the sole runtime source of truth and uses
a global `nodeId` plus explicit `edgeId`; native graph endpoint/type
uniqueness is therefore never allowed to collapse different source releases or
views.
