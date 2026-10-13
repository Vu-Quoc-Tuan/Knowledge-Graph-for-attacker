# ADR-001: CWE is the canonical backbone

Canonical CWE nodes and relations are imported only from a pinned MITRE source
snapshot. Derived context, profiles and inferred relations are stored as
separate entities. This preserves MITRE semantics and makes learned knowledge
retractable without rewriting the canonical ontology.
