# Knowledge planes

CWE is canonical. CAPEC, WSTG and PATT are independent source planes, not a
pipeline. Context, constraint and evidence nodes attach through assertions and
typed relations. A CAPEC `RELATED_WEAKNESS` list never means that every CWE is
simultaneously required.

The PATT raw-payload plane is intentionally compact in the active graph: the
graph stores payload families and technology applicability, while document and
evidence metadata (including their source relationships) live losslessly in the
`compact_details.sqlite3` sidecar. Byte-exact candidate strings and section
locators live in the separate `patt_payloads.sqlite3` sidecar, and API reads
page that index. This keeps provenance and reviewability without treating
every upstream string as a graph entity or as a validated execution fact.
