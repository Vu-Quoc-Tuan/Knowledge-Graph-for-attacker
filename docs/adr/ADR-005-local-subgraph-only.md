# ADR-005: Reason over bounded local subgraphs

Historical retrieval and graph traversal use a typed whitelist and per-plane
budgets. A result records truncation or omitted evidence rather than silently
performing arbitrary-depth traversal across the full graph.
