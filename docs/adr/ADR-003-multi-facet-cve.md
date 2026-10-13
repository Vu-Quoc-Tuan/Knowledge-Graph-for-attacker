# ADR-003: Model a CVE through independent facets

A CVE can have multiple weaknesses, techniques, contexts, constraints and
evidence. No API or reasoner may select a first CWE as its complete
classification. Occurrence-level evidence is required before composition.
