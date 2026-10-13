# Assertion Contract

`WeaknessAssertion` answers which source asserts that one vulnerability maps to
one CWE. It has a unique assertion ID, status, provenance, one or more evidence
spans and optional confidence. Multiple claims for the same CVE/CWE remain
separate when they come from different sources or scopes.

`WeaknessOccurrence` describes the concrete manifestation and is separate from
classification. A chain requires occurrence-level sequence evidence. A
composite is represented by a `CompositionGroup` with `ALL_OF`; a shared pair of
CWE labels never creates a composite by itself.

The only allowed fact statuses are `CANONICAL`, `REPORTED`, `EXTRACTED`,
`OBSERVED`, `INFERRED`, `SUPPORTED`, `VALIDATED` and `REJECTED`. Review status
and execution result are independent fields/workflows.
