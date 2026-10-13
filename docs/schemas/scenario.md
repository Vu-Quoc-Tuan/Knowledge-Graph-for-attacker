# Scenario Contract

A scenario is semantic knowledge for Module 2, not a payload or scanner rule.
It records target vulnerability, weakness set, techniques, constraints,
applicability, confidence components and derivation IDs. It may be inherited,
analogous, chained, composite or novel. Before a fit-for-purpose verification
it remains `INFERRED` or `SUPPORTED`, never `VALIDATED`.

Applicability is three-valued: `APPLICABLE`, `NOT_APPLICABLE` and `UNKNOWN`.
An unavailable configuration, callback channel or version parser produces
`UNKNOWN`; it does not create a negative global fact.
